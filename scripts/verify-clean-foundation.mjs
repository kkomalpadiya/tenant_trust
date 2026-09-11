import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const suffix = `${process.pid}-${randomBytes(4).toString("hex")}`;
const projectName = `tenant-trust-clean-${suffix}`;
const workingDirectory = await mkdtemp(join(tmpdir(), "tenant-trust-foundation-"));
const environmentFile = join(workingDirectory, "foundation.env");
const caPasswordFile = join(workingDirectory, "step-ca-password.txt");
const resourceNames = {
  POSTGRES_VOLUME_NAME: `${projectName}-postgres-data`,
  REDIS_VOLUME_NAME: `${projectName}-redis-data`,
  NATS_VOLUME_NAME: `${projectName}-nats-data`,
  STEP_CA_VOLUME_NAME: `${projectName}-step-ca-data`,
  BACKEND_NETWORK_NAME: `${projectName}-backend`,
};

function run(command, args, label, { allowFailure = false, quiet = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0 && !allowFailure) {
    const detail = (result.stderr || result.stdout).trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  if (!quiet) {
    if (result.stdout.trim()) console.log(result.stdout.trim());
    if (result.stderr.trim()) console.error(result.stderr.trim());
  }
  return result;
}

function compose(args, label, options) {
  return run("docker", [
    "compose",
    "--env-file",
    environmentFile,
    "-f",
    "infra/compose/compose.yaml",
    "--project-name",
    projectName,
    ...args,
  ], label, options);
}

async function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

const template = await readFile(resolve(repositoryRoot, ".env.example"), "utf8");
const settings = Object.fromEntries(
  template.split(/\r?\n/u)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => {
      const separator = line.indexOf("=");
      const key = line.slice(0, separator);
      const value = line.slice(separator + 1);
      return [key, value === "replace-with-a-generated-local-secret" ? randomBytes(36).toString("base64url") : value];
    }),
);

for (const [key, value] of Object.entries(resourceNames)) settings[key] = value;
const ports = await Promise.all(Array.from({ length: 5 }, freePort));
[settings.POSTGRES_HOST_PORT, settings.REDIS_HOST_PORT, settings.NATS_HOST_PORT, settings.STEP_CA_HOST_PORT, settings.OPA_HOST_PORT] = ports.map(String);
settings.STEP_CA_PASSWORD_FILE = caPasswordFile.replaceAll("\\", "/");

await writeFile(environmentFile, `${Object.entries(settings).map(([key, value]) => `${key}=${value}`).join("\n")}\n`, { mode: 0o600 });
await writeFile(caPasswordFile, `${randomBytes(36).toString("base64url")}\n`, { mode: 0o600 });
if (process.platform !== "win32") {
  await chmod(environmentFile, 0o600);
  await chmod(caPasswordFile, 0o600);
}

const childEnvironment = {
  ...process.env,
  TENANT_TRUST_ENV_FILE: environmentFile,
  TENANT_TRUST_COMPOSE_PROJECT: projectName,
};

let primaryFailure;
let cleanupFailure;
try {
  compose(["config", "--quiet"], "isolated Compose configuration", { quiet: true });
  compose(["--profile", "tools", "run", "--rm", "step-ca-init"], "isolated CA initialization");
  compose(["up", "-d", "postgres", "redis", "nats", "step-ca", "opa"], "isolated foundation startup");
  compose(["--profile", "tools", "run", "--rm", "migrate"], "isolated database migration");
  run(process.execPath, ["scripts/verify-foundation.mjs"], "isolated foundation verification");
} catch (error) {
  primaryFailure = error;
} finally {
  const down = compose(["down", "--volumes", "--remove-orphans", "--timeout", "5"], "isolated cleanup", { allowFailure: true });
  if (down.status !== 0) cleanupFailure = new Error((down.stderr || down.stdout).trim() || "isolated cleanup failed");

  for (const name of [...Object.values(resourceNames)]) {
    const type = name.endsWith("-backend") ? "network" : "volume";
    const inspection = run("docker", [type, "inspect", name], `${type} cleanup check`, { allowFailure: true, quiet: true });
    if (inspection.status === 0) cleanupFailure = new Error(`Disposable ${type} ${name} still exists after cleanup.`);
  }
  await rm(workingDirectory, { recursive: true, force: true });
}

if (primaryFailure) throw primaryFailure;
if (cleanupFailure) throw cleanupFailure;
console.log("PASS clean foundation started, verified, and removed only its isolated resources.");
