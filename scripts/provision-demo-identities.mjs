import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const seedSql = readFileSync(
  resolve(repositoryRoot, "database/seeds/001_demo_identities.sql"),
  "utf8",
);

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
  throw new Error(`Demo identity provisioning failed${detail ? `:\n${detail}` : ""}`);
}

if (result.stdout.trim()) console.log(result.stdout.trim());
if (result.stderr.trim()) console.error(result.stderr.trim());
console.log("Demo identity provisioning completed without changing existing lifecycle states.");
