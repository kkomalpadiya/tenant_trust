import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const examplePath = resolve(repositoryRoot, ".env.example");
const environmentPath = resolve(repositoryRoot, ".env");
const runtimeSecretDirectory = resolve(repositoryRoot, "runtime", "secrets");
const stepCaPasswordPath = resolve(runtimeSecretDirectory, "step-ca-password.txt");
const template = await readFile(examplePath, "utf8");
const force = process.argv.includes("--force");
const secretPlaceholder = "replace-with-a-generated-local-secret";
const generateSecret = () => randomBytes(36).toString("base64url");
const resolveTemplateValue = (value) => value === secretPlaceholder ? generateSecret() : value;

let existing = null;
try {
  existing = await readFile(environmentPath, "utf8");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}

let environment;
let message;
let writeEnvironment = true;
if (existing === null || force) {
  environment = template.replaceAll(secretPlaceholder, generateSecret);
  message = force
    ? "Recreated .env and rotated all local service secrets."
    : "Created .env with generated local service secrets.";
} else {
  const existingKeys = new Set(
    existing.split(/\r?\n/u)
      .filter((line) => line && !line.startsWith("#") && line.includes("="))
      .map((line) => line.slice(0, line.indexOf("="))),
  );
  const missing = template.split(/\r?\n/u)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    })
    .filter(([key]) => !existingKeys.has(key))
    .map(([key, value]) => `${key}=${resolveTemplateValue(value)}`);

  if (missing.length === 0) {
    environment = existing;
    writeEnvironment = false;
    message = ".env already contains every documented local setting.";
  } else {
    environment = `${existing.trimEnd()}\n\n# Added by environment synchronization\n${missing.join("\n")}\n`;
    message = `Updated .env with ${missing.length} newly documented local setting(s); existing secrets were preserved.`;
  }
}

if (writeEnvironment) {
  await writeFile(environmentPath, environment, { encoding: "utf8", mode: 0o600 });
  try {
    await chmod(environmentPath, 0o600);
  } catch (error) {
    if (process.platform !== "win32") throw error;
  }
}

await mkdir(runtimeSecretDirectory, { recursive: true });
let stepCaSecretCreated = false;
try {
  await readFile(stepCaPasswordPath, "utf8");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  await writeFile(stepCaPasswordPath, `${generateSecret()}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await chmod(stepCaPasswordPath, 0o600);
  } catch (chmodError) {
    if (process.platform !== "win32") throw chmodError;
  }
  stepCaSecretCreated = true;
}

console.log(message);
if (stepCaSecretCreated) console.log("Created the ignored step-ca password file under runtime/secrets.");
