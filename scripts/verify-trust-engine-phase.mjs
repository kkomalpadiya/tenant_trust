import { spawnSync } from "node:child_process";
import { repositoryRoot } from "./lib/foundation-context.mjs";

const skipRepositoryTests = process.argv.slice(2).includes("--skip-repository-tests");

function run(command, args, label, { shell = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 32 * 1024 * 1024,
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
  if (process.env.npm_execpath) run(process.execPath, [process.env.npm_execpath, ...args], label);
  else run("npm", args, label, { shell: process.platform === "win32" });
}

console.log("\n=== Phase 6: deterministic tests and calibration fixtures ===");
if (skipRepositoryTests) {
  run(process.execPath, ["--test", "test/trust-engine-calibration.test.mjs"], "calibration fixtures");
} else {
  runNpm(["test"], "repository tests");
}

const steps = [
  ["normalized component and model boundaries", "scripts/verify-trust-model-definition.mjs"],
  ["deterministic weighted calculation", "scripts/verify-weighted-trust-score.mjs"],
  ["missing, stale and decay behavior", "scripts/verify-temporal-trust-smoothing.mjs"],
  ["hysteresis, influence and recovery controls", "scripts/verify-trust-transition-controls.mjs"],
  ["evidence replay and ordering", "scripts/verify-evidence-replay.mjs"],
  ["evidence flood and source safeguards", "scripts/verify-evidence-source-safeguards.mjs"],
  ["tenant-scoped versioned trust state", "scripts/verify-trust-state-storage.mjs"],
  ["versioned trust configuration", "scripts/verify-trust-configuration-lifecycle.mjs"],
  ["validated evidence consumption", "scripts/verify-validated-evidence-trust-consumption.mjs"],
  ["durable trust transition explanations", "scripts/verify-trust-transition-explanations.mjs"],
  ["freshness-aware internal score lookup", "scripts/verify-internal-trust-score-lookup.mjs"],
];

for (const [label, script] of steps) {
  console.log(`\n=== Phase 6: ${label} ===`);
  run(process.execPath, [script], label);
}

console.log("\nPhase 6 adaptive trust-engine verification passed.");
console.log("PASS boundaries, missing/stale signals, recovery, floods and replay are deterministic");
console.log("PASS durable state and lookup remain actor-bound and tenant isolated");
console.log("LIMIT prototype defaults remain explicitly unvalidated; this gate makes no effectiveness claim");
