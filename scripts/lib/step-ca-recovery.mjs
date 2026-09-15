import { spawnSync } from "node:child_process";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const MAGIC = Buffer.from("TTCA1\n", "ascii");
const AUTH_TAG_BYTES = 16;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const SCRYPT = Object.freeze({ name: "scrypt", N: 16_384, r: 8, p: 1, keyLength: 32 });
const CIPHER = "aes-256-gcm";
const VOLUME_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;

function run(command, args, label, { encoding = "utf8", allowFailure = false } = {}) {
  const result = spawnSync(command, args, {
    encoding,
    maxBuffer: MAX_ARCHIVE_BYTES + MAX_HEADER_BYTES,
    windowsHide: true,
  });
  if (result.status !== 0 && !allowFailure) {
    const detail = Buffer.isBuffer(result.stderr)
      ? result.stderr.toString("utf8").trim()
      : (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  return result;
}

function assertVolumeName(volumeName) {
  if (!VOLUME_NAME.test(volumeName)) throw new Error("Docker volume name is invalid.");
}

function assertPinnedImage(image) {
  if (!image?.includes("@sha256:")) throw new Error("A digest-pinned step-ca image is required.");
}

function pathIsInside(parent, candidate) {
  const child = relative(resolve(parent), resolve(candidate));
  return child === "" || (!child.startsWith(`..${sep}`) && child !== "..");
}

function assertOutsideRepository(repositoryRoot, targetPath, label) {
  if (!isAbsolute(targetPath)) throw new Error(`${label} must be an absolute path.`);
  if (pathIsInside(repositoryRoot, targetPath)) {
    throw new Error(`${label} must be outside the Git repository.`);
  }
}

async function readPassphrase(passphraseFile, repositoryRoot) {
  assertOutsideRepository(repositoryRoot, passphraseFile, "Backup passphrase file");
  const raw = await readFile(passphraseFile, "utf8");
  const passphrase = raw.replace(/\r?\n$/u, "");
  if (Buffer.byteLength(passphrase, "utf8") < 24) {
    throw new Error("Backup passphrase must contain at least 24 UTF-8 bytes.");
  }
  return passphrase;
}

function inspectVolume(volumeName) {
  return run("docker", ["volume", "inspect", volumeName], `Docker volume ${volumeName} inspection`, {
    allowFailure: true,
  }).status === 0;
}

function assertVolumeStopped(volumeName) {
  const result = run(
    "docker",
    ["ps", "--filter", `volume=${volumeName}`, "--format", "{{.ID}}"],
    `running-container check for ${volumeName}`,
  );
  if (result.stdout.trim()) {
    throw new Error(`Docker volume ${volumeName} is mounted by a running container; stop the issuer before backup.`);
  }
}

function helperRun({ image, volumeName, workingDirectory, command, readOnly = false }) {
  const sourceMount = `type=volume,source=${volumeName},target=/source${readOnly ? ",readonly" : ""}`;
  return run("docker", [
    "run", "--rm", "--user", "0:0", "--entrypoint", "/bin/sh",
    "--mount", sourceMount,
    "--mount", `type=bind,source=${workingDirectory},target=/work`,
    image, "-ec", command,
  ], `step-ca volume operation for ${volumeName}`);
}

function deriveKey(passphrase, salt, kdf = SCRYPT) {
  if (
    kdf.name !== SCRYPT.name
    || kdf.N !== SCRYPT.N
    || kdf.r !== SCRYPT.r
    || kdf.p !== SCRYPT.p
    || kdf.keyLength !== SCRYPT.keyLength
  ) {
    throw new Error("Unsupported backup key-derivation parameters.");
  }
  return scryptSync(passphrase, salt, kdf.keyLength, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: 64 * 1024 * 1024,
  });
}

function encodeBackup(archive, passphrase, sourceVolume) {
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const header = {
    schema: "tenant-trust-step-ca-backup/v1",
    createdAt: new Date().toISOString(),
    sourceVolume,
    archiveSha256: createHash("sha256").update(archive).digest("hex"),
    cipher: CIPHER,
    kdf: SCRYPT,
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
  };
  const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
  const headerLength = Buffer.alloc(4);
  headerLength.writeUInt32BE(headerBytes.length);
  const authenticatedHeader = Buffer.concat([MAGIC, headerLength, headerBytes]);
  const cipher = createCipheriv(CIPHER, deriveKey(passphrase, salt), iv, { authTagLength: AUTH_TAG_BYTES });
  cipher.setAAD(authenticatedHeader);
  const ciphertext = Buffer.concat([cipher.update(archive), cipher.final()]);
  return {
    bytes: Buffer.concat([authenticatedHeader, ciphertext, cipher.getAuthTag()]),
    metadata: header,
  };
}

function decodeBackup(bytes, passphrase) {
  if (bytes.length < MAGIC.length + 4 + AUTH_TAG_BYTES || !bytes.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("Backup does not use the Tenant Trust step-ca backup format.");
  }
  const headerLength = bytes.readUInt32BE(MAGIC.length);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES) throw new Error("Backup header length is invalid.");
  const headerEnd = MAGIC.length + 4 + headerLength;
  if (headerEnd + AUTH_TAG_BYTES >= bytes.length) throw new Error("Backup payload is truncated.");
  const authenticatedHeader = bytes.subarray(0, headerEnd);
  const header = JSON.parse(bytes.subarray(MAGIC.length + 4, headerEnd).toString("utf8"));
  if (header.schema !== "tenant-trust-step-ca-backup/v1" || header.cipher !== CIPHER) {
    throw new Error("Backup format or cipher is unsupported.");
  }
  const salt = Buffer.from(header.salt, "base64url");
  const iv = Buffer.from(header.iv, "base64url");
  if (salt.length !== 32 || iv.length !== 12) throw new Error("Backup cryptographic parameters are invalid.");
  const ciphertext = bytes.subarray(headerEnd, bytes.length - AUTH_TAG_BYTES);
  const tag = bytes.subarray(bytes.length - AUTH_TAG_BYTES);
  const decipher = createDecipheriv(CIPHER, deriveKey(passphrase, salt, header.kdf), iv, {
    authTagLength: AUTH_TAG_BYTES,
  });
  decipher.setAAD(authenticatedHeader);
  decipher.setAuthTag(tag);
  let archive;
  try {
    archive = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("Backup authentication failed; the passphrase is wrong or the backup was changed.");
  }
  const digest = createHash("sha256").update(archive).digest("hex");
  if (digest !== header.archiveSha256) throw new Error("Decrypted backup archive digest does not match its manifest.");
  return { archive, metadata: header };
}

export async function createEncryptedStepCaBackup({
  volumeName,
  outputPath,
  passphraseFile,
  image,
  repositoryRoot,
}) {
  assertVolumeName(volumeName);
  assertPinnedImage(image);
  assertOutsideRepository(repositoryRoot, outputPath, "Backup output");
  if (!outputPath.endsWith(".ttcab")) throw new Error("Backup output must use the .ttcab extension.");
  if (!inspectVolume(volumeName)) throw new Error(`Docker volume ${volumeName} does not exist.`);
  assertVolumeStopped(volumeName);
  const passphrase = await readPassphrase(passphraseFile, repositoryRoot);
  const workingDirectory = await mkdtemp(join(tmpdir(), "tenant-trust-ca-backup-"));
  try {
    helperRun({
      image,
      volumeName,
      workingDirectory,
      readOnly: true,
      command: [
        "test -f /source/config/ca.json",
        "test -f /source/certs/root_ca.crt",
        "test -f /source/certs/intermediate_ca.crt",
        "test -f /source/secrets/root_ca_key",
        "test -f /source/secrets/intermediate_ca_key",
        "test \"$(stat -c %a /source/secrets/root_ca_key)\" = 600",
        "test \"$(stat -c %a /source/secrets/intermediate_ca_key)\" = 600",
        "tar -cf /work/step-ca.tar -C /source .",
      ].join(" && "),
    });
    const archivePath = join(workingDirectory, "step-ca.tar");
    const archiveStat = await stat(archivePath);
    if (archiveStat.size <= 0 || archiveStat.size > MAX_ARCHIVE_BYTES) {
      throw new Error("step-ca archive size is outside the permitted local backup range.");
    }
    const archive = await readFile(archivePath);
    const encrypted = encodeBackup(archive, passphrase, volumeName);
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, encrypted.bytes, { flag: "wx", mode: 0o600 });
    if (process.platform !== "win32") await chmod(outputPath, 0o600);
    return encrypted.metadata;
  } finally {
    await rm(workingDirectory, { recursive: true, force: true });
  }
}

export async function restoreEncryptedStepCaBackup({
  inputPath,
  volumeName,
  passphraseFile,
  image,
  repositoryRoot,
}) {
  assertVolumeName(volumeName);
  assertPinnedImage(image);
  assertOutsideRepository(repositoryRoot, inputPath, "Backup input");
  if (inspectVolume(volumeName)) throw new Error(`Restore target volume ${volumeName} already exists.`);
  const inputStat = await stat(inputPath);
  if (
    inputStat.size <= MAGIC.length
    || inputStat.size > MAX_ARCHIVE_BYTES + MAX_HEADER_BYTES + MAGIC.length + 4 + AUTH_TAG_BYTES
  ) {
    throw new Error("Encrypted backup size is invalid.");
  }
  const passphrase = await readPassphrase(passphraseFile, repositoryRoot);
  const decoded = decodeBackup(await readFile(inputPath), passphrase);
  const workingDirectory = await mkdtemp(join(tmpdir(), "tenant-trust-ca-restore-"));
  let volumeCreated = false;
  try {
    const archivePath = join(workingDirectory, "step-ca.tar");
    await writeFile(archivePath, decoded.archive, { mode: 0o600 });
    run("docker", [
      "volume", "create",
      "--label", "tenant-trust.component=step-ca",
      "--label", "tenant-trust.recovery=restored",
      volumeName,
    ], `restore target volume ${volumeName} creation`);
    volumeCreated = true;
    helperRun({
      image,
      volumeName,
      workingDirectory,
      command: [
        "test -z \"$(find /source -mindepth 1 -maxdepth 1 -print -quit)\"",
        "tar -xf /work/step-ca.tar -C /source",
        "test -f /source/config/ca.json",
        "test -f /source/certs/root_ca.crt",
        "test -f /source/certs/intermediate_ca.crt",
        "test -f /source/secrets/root_ca_key",
        "test -f /source/secrets/intermediate_ca_key",
        "test \"$(stat -c %a /source/secrets/root_ca_key)\" = 600",
        "test \"$(stat -c %a /source/secrets/intermediate_ca_key)\" = 600",
      ].join(" && "),
    });
    return decoded.metadata;
  } catch (error) {
    if (volumeCreated) {
      run("docker", ["volume", "rm", volumeName], `failed restore volume ${volumeName} cleanup`, {
        allowFailure: true,
      });
    }
    throw error;
  } finally {
    decoded.archive.fill(0);
    await rm(workingDirectory, { recursive: true, force: true });
  }
}
