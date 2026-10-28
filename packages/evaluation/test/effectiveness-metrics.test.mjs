import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  AUTHORIZATION_MODE_IDS,
} from "@tenant-trust/authorization";
import {
  EFFECTIVENESS_REPORT_ID,
  JWT_RBAC_BASELINE_MODE_ID,
  createEvaluationWorkloadPlan,
  createReferenceEffectivenessAdapters,
  measureEffectivenessAndIsolation,
  runEvaluationWorkload,
} from "../src/index.mjs";

const configurationHash = createHash("sha256").update("effectiveness-metrics-test-v1").digest("hex");
let evaluationPromise;

async function evaluation() {
  evaluationPromise ??= (async () => {
    const plan = createEvaluationWorkloadPlan({ configurationHash });
    const workload = await runEvaluationWorkload({ plan, adapters: createReferenceEffectivenessAdapters() });
    return { plan, workload, report: measureEffectivenessAndIsolation(workload) };
  })();
  return evaluationPromise;
}

function mode(report, modeId) {
  return report.modes.find((entry) => entry.modeId === modeId);
}

test("effectiveness report requires full protocol-evaluation coverage", async () => {
  const verificationPlan = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  const verification = await runEvaluationWorkload({ plan: verificationPlan, adapters: createReferenceEffectivenessAdapters() });
  assert.throws(() => measureEffectivenessAndIsolation(verification), /full protocol-evaluation/u);
  const { report } = await evaluation();
  assert.equal(report.reportId, EFFECTIVENESS_REPORT_ID);
  assert.equal(report.modes.length, 3);
  assert.ok(report.modes.every(({ measuredTrials }) => measuredTrials === 12_300));
});

test("unsupported controls remain security misses with explicit denominators", async () => {
  const { report } = await evaluation();
  for (const modeId of [JWT_RBAC_BASELINE_MODE_ID, AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE]) {
    const metrics = mode(report, modeId).metrics;
    assert.equal(metrics.attackDetectionRate.numerator, 1_230);
    assert.equal(metrics.attackDetectionRate.denominator, 8_610);
    assert.equal(metrics.attackDetectionRate.estimate, 0.142857);
    assert.equal(metrics.replayRejectionRate.numerator, 0);
    assert.equal(metrics.auditModificationDetectionRate.numerator, 0);
    assert.equal(metrics.ledgerVerificationRate.numerator, 0);
  }
});

test("false restrictions and isolation failures use the registered trial populations", async () => {
  const { report } = await evaluation();
  for (const entry of report.modes) {
    assert.equal(entry.metrics.falseRestrictionRate.denominator, 1_230);
    assert.equal(entry.metrics.falseRestrictionRate.numerator, 0);
  }
  for (const modeId of [JWT_RBAC_BASELINE_MODE_ID, AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE]) {
    const isolation = mode(report, modeId).metrics.tenantIsolationRate;
    assert.equal(isolation.denominator, 2_460);
    assert.equal(isolation.numerator, 1_230);
    assert.equal(isolation.isolationFailures, 1_230);
  }
  const proposed = mode(report, AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA).metrics.tenantIsolationRate;
  assert.equal(proposed.estimate, 1);
  assert.equal(proposed.isolationFailures, 0);
});

test("revocation delay reports successful observations and unbounded failures separately", async () => {
  const { report } = await evaluation();
  for (const modeId of [JWT_RBAC_BASELINE_MODE_ID, AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE]) {
    const delay = mode(report, modeId).metrics.revocationEnforcementDelay;
    assert.equal(delay.denominator, 1_230);
    assert.equal(delay.successfulObservations, 0);
    assert.equal(delay.unboundedFailures, 1_230);
    assert.equal(delay.medianMs, null);
  }
  const proposed = mode(report, AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA).metrics.revocationEnforcementDelay;
  assert.equal(proposed.successfulObservations, 1_230);
  assert.equal(proposed.unboundedFailures, 0);
  assert.ok(proposed.medianMs >= 240 && proposed.medianMs <= 320);
  assert.ok(proposed.p95Ms >= proposed.medianMs);
});

test("every rate carries deterministic pre-registered uncertainty and the report is immutable", async () => {
  const { report } = await evaluation();
  assert.equal(report.uncertainty.resamples, 10_000);
  for (const entry of report.modes) {
    for (const [name, metric] of Object.entries(entry.metrics)) {
      assert.equal(metric.confidenceInterval.resamples, 10_000, name);
      assert.equal(metric.confidenceInterval.level, 0.95, name);
    }
  }
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.modes[0].metrics), true);
});
