import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const stateFixture = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-trust-state-storage.sql"),
  "utf8",
);
const transitionFixture = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-trust-transition-explanations.sql"),
  "utf8",
);
const lookupVerification = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-internal-trust-score-lookup.sql"),
  "utf8",
);
const rollbackMarker = "\nROLLBACK;";
assert.ok(stateFixture.includes(rollbackMarker), "trust-state fixture rollback marker is missing");
const verificationSql = stateFixture.replace(
  rollbackMarker,
  `\n${transitionFixture}\n${lookupVerification}\nROLLBACK;`,
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
    input: verificationSql,
    maxBuffer: 5 * 1024 * 1024,
  },
);

if (result.status !== 0) {
  const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
  throw new Error(`Internal trust-score lookup verification failed${detail ? `:\n${detail}` : ""}`);
}

if (result.stdout.trim()) console.log(result.stdout.trim());
if (result.stderr.trim()) console.error(result.stderr.trim());
console.log("Internal trust-score lookup verification passed without retaining test changes.");
