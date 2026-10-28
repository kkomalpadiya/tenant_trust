import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { AUTHORIZATION_MODE_IDS } from "@tenant-trust/authorization";
import {
  EFFECTIVENESS_REPORT_ID,
  EVALUATION_PROTOCOL_ID,
  JWT_RBAC_BASELINE_MODE_ID,
  REFERENCE_EFFECTIVENESS_ADAPTER_ID,
  WORKLOAD_RUNNER_ID,
  createEvaluationWorkloadPlan,
  createReferenceEffectivenessAdapters,
  measureEffectivenessAndIsolation,
  runEvaluationWorkload,
} from "../packages/evaluation/src/index.mjs";

const configurationHash = createHash("sha256")
  .update([EVALUATION_PROTOCOL_ID, WORKLOAD_RUNNER_ID, REFERENCE_EFFECTIVENESS_ADAPTER_ID].join("/"))
  .digest("hex");
const plan = createEvaluationWorkloadPlan({ configurationHash });
const workload = await runEvaluationWorkload({ plan, adapters: createReferenceEffectivenessAdapters() });
const report = measureEffectivenessAndIsolation(workload);
const byMode = new Map(report.modes.map((entry) => [entry.modeId, entry]));
const proposed = byMode.get(AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA);

assert.equal(report.reportId, EFFECTIVENESS_REPORT_ID);
assert.equal(plan.runs.length, 3_150);
assert.equal(plan.runs.filter(({ sampleKind }) => sampleKind === "measured").length, 2_700);
assert.equal(report.modes.length, 3);
assert.ok(report.modes.every(({ measuredTrials }) => measuredTrials === 12_300));
assert.equal(byMode.get(JWT_RBAC_BASELINE_MODE_ID).metrics.attackDetectionRate.estimate, 0.142857);
assert.equal(byMode.get(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE).metrics.attackDetectionRate.estimate, 0.142857);
assert.equal(proposed.metrics.attackDetectionRate.estimate, 1);
assert.equal(proposed.metrics.falseRestrictionRate.estimate, 0);
assert.equal(proposed.metrics.tenantIsolationRate.isolationFailures, 0);
assert.equal(proposed.metrics.auditModificationDetectionRate.estimate, 1);
assert.equal(proposed.metrics.ledgerVerificationRate.estimate, 1);
assert.equal(proposed.metrics.revocationEnforcementDelay.unboundedFailures, 0);
assert.ok(report.modes.every(({ metrics }) => Object.values(metrics).every(({ confidenceInterval }) => (
  confidenceInterval.resamples === 10_000 && confidenceInterval.level === 0.95
))));

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log("Effectiveness and tenant-isolation evaluation passed.");
  console.log(`Report: ${report.reportId}`);
  console.log(`Measured trials: ${report.modes.reduce((total, entry) => total + entry.measuredTrials, 0)}`);
  console.log(`Measured observations: ${report.measuredObservationCount}`);
  for (const entry of report.modes) {
    const { metrics } = entry;
    console.log([
      entry.modeId,
      `detection=${(metrics.attackDetectionRate.estimate * 100).toFixed(2)}%`,
      `false-restriction=${(metrics.falseRestrictionRate.estimate * 100).toFixed(2)}%`,
      `isolation=${(metrics.tenantIsolationRate.estimate * 100).toFixed(2)}%`,
      `audit=${(metrics.auditModificationDetectionRate.estimate * 100).toFixed(2)}%`,
      `ledger=${(metrics.ledgerVerificationRate.estimate * 100).toFixed(2)}%`,
      `revocation-median-ms=${metrics.revocationEnforcementDelay.medianMs ?? "unbounded"}`,
    ].join(" "));
  }
  console.log("Scope: deterministic reference functional evaluation; performance remains deferred to T10.8.");
}
