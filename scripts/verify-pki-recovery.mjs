import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";
import {
  createEncryptedStepCaBackup,
  restoreEncryptedStepCaBackup,
} from "./lib/step-ca-recovery.mjs";

const image = environment.STEP_CA_IMAGE;
if (!image?.includes("@sha256:")) throw new Error("STEP_CA_IMAGE must be digest-pinned.");

const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const sourceVolume = `tenant-trust-recovery-source-${suffix}`;
const restoredVolume = `tenant-trust-recovery-target-${suffix}`;
const rejectedVolume = `tenant-trust-recovery-rejected-${suffix}`;
const containerName = `tenant-trust-recovered-ca-${suffix}`;
const workingDirectory = await mkdtemp(join(tmpdir(), "tenant-trust-pki-recovery-"));
const caPasswordFile = join(workingDirectory, "ca-password.txt");
const backupPassphraseFile = join(workingDirectory, "backup-passphrase.txt");
const wrongPassphraseFile = join(workingDirectory, "wrong-passphrase.txt");
const backupPath = join(workingDirectory, "issuer-backup.ttcab");
const runningBackupPath = join(workingDirectory, "running-issuer-backup.ttcab");
const initScript = resolve(repositoryRoot, "infra", "pki", "init-step-ca.sh");
const issuanceScript = resolve(repositoryRoot, "infra", "pki", "verify-issuance.sh");

function run(command, args, label, { allowFailure = false, encoding = "utf8" } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding,
    maxBuffer: 16 * 1024 * 1024,
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

function volumeExists(name) {
  return run("docker", ["volume", "inspect", name], `${name} inspection`, { allowFailure: true }).status === 0;
}

function volumeBytes(name, path) {
  return run("docker", [
    "run", "--rm", "--entrypoint", "/bin/cat",
    "--mount", `type=volume,source=${name},target=/home/step,readonly`,
    image, path,
  ], `${name} ${path} read`, { encoding: null }).stdout;
}

async function waitForRecoveredCa() {
  const deadline = Date.now() + 60_000;
  let lastDetail = "container not started";
  while (Date.now() < deadline) {
    const health = run("docker", [
      "exec", containerName,
      "step", "ca", "health",
      "--ca-url", "https://localhost:9000",
      "--root", "/home/step/certs/root_ca.crt",
    ], "recovered CA health", { allowFailure: true });
    lastDetail = (health.stderr || health.stdout).trim();
    if (health.status === 0) return;
    await new Promise((complete) => setTimeout(complete, 1_000));
  }
  throw new Error(`Recovered CA did not become healthy: ${lastDetail}`);
}

let primaryFailure;
let cleanupFailure;
try {
  await writeFile(caPasswordFile, `${randomBytes(36).toString("base64url")}\n`, { mode: 0o600 });
  await writeFile(backupPassphraseFile, `${randomBytes(36).toString("base64url")}\n`, { mode: 0o600 });
  await writeFile(wrongPassphraseFile, `${randomBytes(36).toString("base64url")}\n`, { mode: 0o600 });
  if (process.platform !== "win32") {
    await Promise.all([caPasswordFile, backupPassphraseFile, wrongPassphraseFile].map((path) => chmod(path, 0o600)));
  }

  run("docker", ["volume", "create", "--label", "tenant-trust.recovery=test-source", sourceVolume], "source volume creation");
  run("docker", [
    "run", "--rm", "--entrypoint", "/bin/sh",
    "--mount", `type=volume,source=${sourceVolume},target=/home/step`,
    "--mount", `type=bind,source=${initScript},target=/scripts/init-step-ca.sh,readonly`,
    "--mount", `type=bind,source=${caPasswordFile},target=/run/secrets/step_ca_password,readonly`,
    "--env", "STEP_CA_NAME=Tenant Trust Recovery Test CA",
    "--env", "STEP_CA_DNS_NAMES=localhost",
    "--env", "STEP_CA_ADDRESS=:9000",
    "--env", "STEP_CA_PROVISIONER=platform-admin",
    image, "/scripts/init-step-ca.sh",
  ], "disposable source CA initialization");

  const sourceRootDigest = createHash("sha256")
    .update(volumeBytes(sourceVolume, "/home/step/certs/root_ca.crt"))
    .digest("hex");
  await createEncryptedStepCaBackup({
    volumeName: sourceVolume,
    outputPath: backupPath,
    passphraseFile: backupPassphraseFile,
    image,
    repositoryRoot,
  });
  const encryptedBackup = await readFile(backupPath);
  assert.ok(encryptedBackup.subarray(0, 6).equals(Buffer.from("TTCA1\n", "ascii")));
  assert.equal(encryptedBackup.includes(Buffer.from("PRIVATE KEY", "ascii")), false);
  assert.equal(encryptedBackup.includes(Buffer.from("BEGIN CERTIFICATE", "ascii")), false);
  if (process.platform !== "win32") assert.equal((await stat(backupPath)).mode & 0o777, 0o600);
  console.log("PASS stopped issuer state was archived and authenticated encryption hides certificates and private keys");

  await assert.rejects(
    restoreEncryptedStepCaBackup({
      inputPath: backupPath,
      volumeName: rejectedVolume,
      passphraseFile: wrongPassphraseFile,
      image,
      repositoryRoot,
    }),
    /authentication failed/u,
  );
  assert.equal(volumeExists(rejectedVolume), false);
  console.log("PASS wrong passphrases fail before a restore volume is created");

  const restoredMetadata = await restoreEncryptedStepCaBackup({
    inputPath: backupPath,
    volumeName: restoredVolume,
    passphraseFile: backupPassphraseFile,
    image,
    repositoryRoot,
  });
  assert.equal(restoredMetadata.sourceVolume, sourceVolume);
  const restoredRootDigest = createHash("sha256")
    .update(volumeBytes(restoredVolume, "/home/step/certs/root_ca.crt"))
    .digest("hex");
  assert.equal(restoredRootDigest, sourceRootDigest);
  console.log("PASS restore created a distinct volume with the original public trust identity");

  await assert.rejects(
    restoreEncryptedStepCaBackup({
      inputPath: backupPath,
      volumeName: sourceVolume,
      passphraseFile: backupPassphraseFile,
      image,
      repositoryRoot,
    }),
    /already exists/u,
  );
  console.log("PASS restore refuses to overwrite an existing CA volume");

  const modes = run("docker", [
    "run", "--rm", "--entrypoint", "/bin/sh",
    "--mount", `type=volume,source=${restoredVolume},target=/home/step,readonly`,
    image, "-ec",
    "stat -c '%a %n' /home/step/secrets/root_ca_key /home/step/secrets/intermediate_ca_key",
  ], "restored key permission check").stdout.trim().split(/\r?\n/u);
  assert.deepEqual(modes.sort(), [
    "600 /home/step/secrets/intermediate_ca_key",
    "600 /home/step/secrets/root_ca_key",
  ]);
  console.log("PASS restored root and intermediate keys retain owner-only 0600 permissions");

  run("docker", [
    "run", "-d", "--name", containerName, "--entrypoint", "step-ca",
    "--mount", `type=volume,source=${restoredVolume},target=/home/step`,
    "--mount", `type=bind,source=${caPasswordFile},target=/run/secrets/step_ca_password,readonly`,
    "--mount", `type=bind,source=${issuanceScript},target=/scripts/verify-issuance.sh,readonly`,
    image,
    "/home/step/config/ca.json", "--password-file", "/run/secrets/step_ca_password",
  ], "recovered CA startup");
  await waitForRecoveredCa();
  await assert.rejects(
    createEncryptedStepCaBackup({
      volumeName: restoredVolume,
      outputPath: runningBackupPath,
      passphraseFile: backupPassphraseFile,
      image,
      repositoryRoot,
    }),
    /running container/u,
  );
  console.log("PASS backup refuses a live issuer volume to prevent an inconsistent snapshot");
  run("docker", ["exec", containerName, "/bin/sh", "/scripts/verify-issuance.sh"], "recovered CA issuance proof");
  console.log("PASS recovered CA became healthy and issued a newly verified disposable certificate");

  const trackedFiles = run("git", ["ls-files"], "tracked-file inventory").stdout.trim().split(/\r?\n/u).filter(Boolean);
  assert.equal(trackedFiles.some((path) => /(^|\/)(runtime|data|outputs|artifacts)\//u.test(path)), false);
  assert.equal(trackedFiles.some((path) => /\.(key|pem|p12|pfx|jks|keystore|ttcab)$/iu.test(path)), false);
  console.log("PASS Git tracks no CA keys, generated runtime state or encrypted backup artifacts");
} catch (error) {
  primaryFailure = error;
} finally {
  run("docker", ["rm", "-f", containerName], "recovered CA container cleanup", { allowFailure: true });
  for (const volume of [sourceVolume, restoredVolume, rejectedVolume]) {
    run("docker", ["volume", "rm", volume], `${volume} cleanup`, { allowFailure: true });
    if (volumeExists(volume)) cleanupFailure = new Error(`Disposable Docker volume ${volume} still exists.`);
  }
  await rm(workingDirectory, { recursive: true, force: true });
}

if (primaryFailure) throw primaryFailure;
if (cleanupFailure) throw cleanupFailure;
console.log("PASS disposable recovery resources and plaintext staging data were removed");
console.log("PKI key-protection and recovery verification passed.");
