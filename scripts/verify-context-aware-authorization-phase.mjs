import { spawnSync } from "node:child_process";
import { repositoryRoot } from "./lib/foundation-context.mjs";

const scenarioOnly = process.argv.slice(2).includes("--scenario-only");

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

const phaseGates = [
  ["policy-contract:verify", "OPA decision contract"],
  ["policy-bundles:verify", "tenant policy bundle lifecycle"],
  ["adaptive-policy:verify", "adaptive score and sensitivity policy"],
  ["step-up-authentication:verify", "bound step-up authentication"],
  ["policy-outcomes:verify", "DENY and QUARANTINE enforcement"],
  ["policy-resilience:verify", "policy outage and state freshness"],
  ["policy-matrix:verify", "adaptive authorization decision matrix"],
  ["policy-provenance:verify", "complete decision provenance"],
];

if (!scenarioOnly) {
  for (const [script, label] of phaseGates) {
    console.log(`\n=== Phase 7: ${label} ===`);
    runNpm(script, label);
  }
}

console.log("\n=== Phase 7: adaptive authorization scenario ===");
runNpm("adaptive-authorization-scenario:verify", "adaptive authorization scenario");

console.log("\nPhase 7 context-aware authorization verification passed.");
console.log("PASS identity, tenant, role, trust, resource, request and policy state remain decision-bound");
console.log("PASS fresh risky evidence changes an explainable trust transition and restricts sensitive access");
console.log("LIMIT prototype trust weights and policy thresholds remain explicitly unvalidated");
