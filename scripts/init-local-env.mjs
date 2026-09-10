import { randomBytes } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const examplePath = resolve(repositoryRoot, ".env.example");
const environmentPath = resolve(repositoryRoot, ".env");
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
    console.log(".env already contains every documented local setting.");
    process.exit(0);
  }
  environment = `${existing.trimEnd()}\n\n# Added by environment synchronization\n${missing.join("\n")}\n`;
  message = `Updated .env with ${missing.length} newly documented local setting(s); existing secrets were preserved.`;
}

await writeFile(environmentPath, environment, { encoding: "utf8", mode: 0o600 });
try {
  await chmod(environmentPath, 0o600);
} catch (error) {
  if (process.platform !== "win32") throw error;
}

console.log(message);
