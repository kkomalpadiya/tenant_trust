import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

function run(command, args, label, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());
}

run(
  "docker",
  [...composeArgs, "exec", "-T", "step-ca", "/bin/sh", "/scripts/verify-revocation.sh"],
  "Smallstep revocation verification",
);

const verificationSql = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-certificate-revocation.sql"),
  "utf8",
);
run(
  "docker",
  [
    ...composeArgs,
    "exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", environment.POSTGRES_USER, "-d", environment.POSTGRES_DB,
  ],
  "PostgreSQL revocation verification",
  { input: verificationSql },
);

console.log("Certificate revocation verification passed without retaining database test changes or probe files.");
