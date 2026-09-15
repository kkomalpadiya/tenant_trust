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

if (!skipUnitTests) runNpm(["test"], "repository unit tests");

for (const [label, script] of [
  ["tenant CA definition", "scripts/verify-tenant-ca-definition.mjs"],
  ["certificate issuance", "scripts/verify-certificate-issuance.mjs"],
  ["certificate inventory", "scripts/verify-certificate-inventory.mjs"],
  ["certificate renewal", "scripts/verify-certificate-renewal.mjs"],
  ["certificate revocation", "scripts/verify-certificate-revocation.mjs"],
  ["certificate event outbox", "scripts/verify-certificate-event-outbox.mjs"],
  ["signed certificate events", "scripts/verify-signed-certificate-events.mjs"],
  ["PKI key protection and recovery", "scripts/verify-pki-recovery.mjs"],
  ["certificate lifecycle boundaries", "scripts/verify-certificate-lifecycle-boundaries.mjs"],
]) {
  console.log(`\n=== Phase 3: ${label} ===`);
  run(process.execPath, [script], label);
}

console.log("\nPhase 3 certificate lifecycle verification passed.");

