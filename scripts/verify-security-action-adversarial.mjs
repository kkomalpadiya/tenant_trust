import { spawnSync } from "node:child_process";
import { repositoryRoot } from "./lib/foundation-context.mjs";

function run(command, args, label, { shell = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 64 * 1024 * 1024,
    shell,
    windowsHide: true,
  });
  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
}

function runNpm(args, label) {
  if (process.env.npm_execpath) {
    run(process.execPath, [process.env.npm_execpath, ...args], label);
  } else {
    run("npm", args, label, { shell: process.platform === "win32" });
  }
}

console.log("\n=== T9.8: adversarial action and recovery unit scenarios ===");
runNpm(["run", "test:orchestrator"], "orchestrator adversarial tests");

console.log("\n=== T9.8: database safeguards ===");
runNpm(["run", "infra:migrate"], "database migrations");

const gates = [
  ["repeated action and retry suppression", "scripts/verify-security-action-orchestration.mjs"],
  ["certificate feedback replay and non-recursion", "scripts/verify-certificate-lifecycle-trust-feedback.mjs"],
  ["session/cache invalidation replay", "scripts/verify-security-state-invalidation.mjs"],
  ["concurrent and stale recovery rejection", "scripts/verify-governed-security-recovery.mjs"],
];

for (const [label, script] of gates) {
  console.log(`\n=== T9.8: ${label} ===`);
  run(process.execPath, [script], label);
}

console.log("\nT9.8 adversarial security-action verification passed.");
console.log("PASS repeated triggers and delivery replays apply no second security effect");
console.log("PASS one-source compromise cannot authorize revocation or recovery");
console.log("PASS concurrent or stale recovery cannot silently restore access");
