import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const seedDirectory = resolve(repositoryRoot, "database/seeds");
const seedFiles = readdirSync(seedDirectory)
  .filter((name) => /^\d+_[A-Za-z0-9_-]+\.sql$/u.test(name))
  .sort();

for (const seedFile of seedFiles) {
  const seedSql = readFileSync(resolve(seedDirectory, seedFile), "utf8");
  const result = spawnSync(
    "docker",
    [
      ...composeArgs,
      "exec",
      "-T",
      "postgres",
      "psql",
      "-X",
      "-v",
      "ON_ERROR_STOP=1",
      "-U",
      environment.POSTGRES_USER,
      "-d",
      environment.POSTGRES_DB,
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      input: seedSql,
      maxBuffer: 4 * 1024 * 1024,
    },
  );

  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`Demo provisioning failed for ${seedFile}${detail ? `:\n${detail}` : ""}`);
  }

  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());
}

console.log("Demo identity, resource and security configuration provisioning completed without changing existing lifecycle states.");
