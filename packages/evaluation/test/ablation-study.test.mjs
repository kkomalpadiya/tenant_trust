import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ABLATION_STUDY_ID,
  EVALUATION_REFERENCE_RESULTS,
  createAblationStudy,
} from "../src/index.mjs";

const study = createAblationStudy();

test("ablation study preserves the measured baseline and proposed-mode comparisons", () => {
  assert.equal(study.studyId, ABLATION_STUDY_ID);
  assert.equal(study.referenceResults, EVALUATION_REFERENCE_RESULTS);
  assert.deepEqual(study.modeComparison.map((mode) => ({
    modeId: mode.modeId,
    attackDetectionPercent: mode.attackDetectionPercent,
    tenantIsolationPercent: mode.tenantIsolationPercent,
  })), [
    { modeId: "jwt-rbac-baseline-v1", attackDetectionPercent: 14.29, tenantIsolationPercent: 50 },
    { modeId: "pki-rbac-baseline-v1", attackDetectionPercent: 14.29, tenantIsolationPercent: 50 },
    { modeId: "adaptive-trust-opa-v1", attackDetectionPercent: 100, tenantIsolationPercent: 100 },
  ]);
});

test("smoothing ablation exposes noise suppression and response-delay tradeoffs", () => {
  const [configured, none] = study.ablations.smoothing.variants;
  assert.equal(configured.transientRestrictedSamples, 0);
  assert.equal(configured.transientThresholdTransitions, 0);
  assert.equal(none.transientRestrictedSamples, 1);
  assert.equal(none.transientThresholdTransitions, 2);
  assert.equal(configured.attackSamplesToRestriction, 2);
  assert.equal(none.attackSamplesToRestriction, 1);
  assert.equal(configured.recoverySamplesToNormal, 2);
  assert.equal(none.recoverySamplesToNormal, 1);
});

test("feedback ablation is bound to the implemented non-recursive controls", () => {
  const { implementationControls, variants } = study.ablations.feedback;
  assert.equal(implementationControls.exactlyOnceTrustEffect, "at-least-once-delivery-exactly-once-trust-effect");
  assert.equal(implementationControls.securityActionEligibility, false);
  assert.deepEqual(implementationControls.terminalNonTriggerKinds, ["certificate-revoked"]);
  assert.deepEqual(variants.map(({ additionalRecursiveActionExecutions, converged }) => ({
    additionalRecursiveActionExecutions, converged,
  })), [
    { additionalRecursiveActionExecutions: 0, converged: true },
    { additionalRecursiveActionExecutions: 5, converged: false },
  ]);
});

test("ledger ablation keeps measured delay separate from its synchronous counterfactual", () => {
  assert.deepEqual(study.ablations.ledger.loads, [
    { load: 1, asynchronousRequestP95Milliseconds: 16.927, synchronousCounterfactualP95Milliseconds: 2207.286, p95InflationFactor: 130.4 },
    { load: 8, asynchronousRequestP95Milliseconds: 16.417, synchronousCounterfactualP95Milliseconds: 2206.776, p95InflationFactor: 134.4 },
    { load: 32, asynchronousRequestP95Milliseconds: 18.666, synchronousCounterfactualP95Milliseconds: 2209.025, p95InflationFactor: 118.3 },
  ]);
  assert.equal(study.ablations.ledger.implementedOutageBehavior, "authorization-continues-and-outbox-reconciles");
});

test("research claims remain immutable and exclude unsupported novelty and generalization", () => {
  assert.equal(Object.isFrozen(study), true);
  assert.equal(Object.isFrozen(study.ablations.smoothing.variants), true);
  assert.equal(study.claimBoundary.notClaimed.length, 4);
  assert.match(study.claimBoundary.contribution, /integration/u);
  assert.ok(study.claimBoundary.notClaimed.some((claim) => claim.includes("novel cryptographic")));
  assert.ok(study.claimBoundary.notClaimed.some((claim) => claim.includes("production performance")));
});
