import { spawnSync } from "node:child_process";
import { repositoryRoot } from "./lib/foundation-context.mjs";

const skipUnitTests = process.argv.slice(2).includes("--skip-unit-tests");

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

if (!skipUnitTests) runNpm(["test"], "repository tests");

const steps = [
  ["gateway mTLS, spoofing and direct-bypass boundary", "node", ["scripts/verify-mtls-gateway.mjs"]],
  ["certificate-authenticated profile and record actions", "node", ["scripts/verify-profile-record-api.mjs"]],
  ["role, action and resource-sensitivity matrix", "npm", ["run", "test:authorization"]],
  ["role-denied and tenant-scoped sensitive operations", "node", ["scripts/verify-sensitive-demo-operations.mjs"]],
  ["explicit PKI plus RBAC baseline mode", "node", ["scripts/verify-pki-rbac-baseline.mjs"]],
  ["revocation and current request-state enforcement", "node", ["scripts/verify-request-state-revalidation.mjs"]],
  ["request-audit schema and least privilege", "node", ["scripts/verify-api-request-audit.mjs"]],
  ["correlated request outcome capture", "node", ["scripts/verify-request-outcome-audit.mjs"]],
  ["request-safeguard schema and least privilege", "node", ["scripts/verify-api-request-safeguards.mjs"]],
  ["session, timeout and replay safeguards", "node", ["scripts/verify-request-safeguards.mjs"]],
];

for (const [label, command, args] of steps) {
  console.log(`\n=== Phase 4: ${label} ===`);
  if (command === "npm") runNpm(args, label);
  else run(process.execPath, args, label);
}

console.log("\nPhase 4 protected SaaS baseline verification passed.");
console.log("PASS allowed actions, role denial, cross-tenant denial, certificate revocation and bypass attempts are covered");
console.log("PASS request audit, session, timeout and replay controls remain fail closed and data-minimized");
