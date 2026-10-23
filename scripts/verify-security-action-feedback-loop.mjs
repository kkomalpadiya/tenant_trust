import { spawnSync } from "node:child_process";
import { repositoryRoot } from "./lib/foundation-context.mjs";

function runNpm(script, label) {
  const command = process.env.npm_execpath ? process.execPath : "npm";
  const args = process.env.npm_execpath
    ? [process.env.npm_execpath, "run", script]
    : ["run", script];
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 64 * 1024 * 1024,
    shell: !process.env.npm_execpath && process.platform === "win32",
    windowsHide: true,
  });
  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
}

const feedbackLoopGates = [
  ["adaptive-authorization-scenario:verify", "risky evidence, trust and policy restriction"],
  ["security-action-rules:verify", "justified action selection and recovery eligibility"],
  ["security-action-orchestration:verify", "durable action execution and retry history"],
  ["certificate-trust-feedback:verify", "authenticated certificate feedback without recursion"],
  ["security-state-invalidation:verify", "session and cached-state enforcement"],
  ["security-recovery:verify", "governed recovery and certificate replacement"],
  ["security-action-audit:verify", "verifiable action and recovery history"],
  ["security-action-adversarial:verify", "replay, oscillation and recovery conflicts"],
  ["security-action-operations:verify", "restart recovery and audit-aware failure visibility"],
];

for (const [script, label] of feedbackLoopGates) {
  console.log(`\n=== Phase 9: ${label} ===`);
  runNpm(script, label);
}

console.log("\nPhase 9 complete security feedback-loop verification passed.");
console.log("PASS risky evidence changes explainable trust and quarantines sensitive access");
console.log("PASS justified actions execute once and feed certificate outcomes back without recursion");
console.log("PASS immutable audit expectations preserve the causal action and recovery history");
console.log("PASS governed recovery stays state-bound, replay-safe and operationally recoverable");
console.log("LIMIT prototype trust weights and policy thresholds remain explicitly unvalidated");
