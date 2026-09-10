import { randomBytes } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const examplePath = resolve(repositoryRoot, ".env.example");
const environmentPath = resolve(repositoryRoot, ".env");
const force = process.argv.includes("--force");

if (!force) {
  try {
    await readFile(environmentPath, "utf8");
    console.error(".env already exists. Use --force only when you intend to rotate local secrets.");
    process.exit(1);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

const template = await readFile(examplePath, "utf8");
const secrets = [randomBytes(36).toString("base64url"), randomBytes(36).toString("base64url")];
let secretIndex = 0;
const environment = template.replaceAll(
  "replace-with-a-generated-local-secret",
  () => secrets[secretIndex++],
);

await writeFile(environmentPath, environment, { encoding: "utf8", mode: 0o600 });
try {
  await chmod(environmentPath, 0o600);
} catch (error) {
  if (process.platform !== "win32") throw error;
}

console.log("Created .env with generated local PostgreSQL and Redis secrets.");
