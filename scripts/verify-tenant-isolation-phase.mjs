import { spawnSync } from "node:child_process";
import { repositoryRoot } from "./lib/foundation-context.mjs";

const steps = [
  ["deterministic Tenant Alpha and Tenant Beta provisioning", "scripts/provision-demo-identities.mjs"],
  ["provisioned identity and configuration checks", "scripts/verify-demo-provisioning.mjs"],
  ["tenant identity and role model checks", "scripts/verify-identity-model.mjs"],
  ["actor-bound PostgreSQL query isolation", "scripts/verify-database-isolation.mjs"],
  ["resource and membership authorization", "scripts/verify-resource-membership-isolation.mjs"],
  ["tenant-owned security configuration", "scripts/verify-security-configuration.mjs"],
  ["cross-tenant identifier tampering denial", "scripts/verify-cross-tenant-tampering.mjs"],
  ["tenant-scoped Redis cache and NATS event delivery", "scripts/verify-runtime-isolation.mjs"],
  ["tenant suspension, recovery and teardown", "scripts/verify-tenant-lifecycle.mjs"],
];

for (const [label, script] of steps) {
  console.log(`\n=== Phase 2: ${label} ===`);
  const result = spawnSync(process.execPath, [script], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });

  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());
  if (result.status !== 0) {
    const detail = result.error?.message || `exit code ${result.status}`;
    throw new Error(`Tenant isolation phase failed during ${label}: ${detail}`);
  }
}

console.log("\nTenant isolation phase verification passed for Tenant Alpha and Tenant Beta.");
