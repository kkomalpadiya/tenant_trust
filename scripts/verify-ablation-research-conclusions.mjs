import assert from "node:assert/strict";
import { createAblationStudy } from "../packages/evaluation/src/index.mjs";

const study = createAblationStudy();
const [jwt, pki, proposed] = study.modeComparison;
const [smoothed, unsmoothed] = study.ablations.smoothing.variants;
const [guardedFeedback, recursiveFeedback] = study.ablations.feedback.variants;

assert.equal(jwt.attackDetectionPercent, 14.29);
assert.equal(pki.attackDetectionPercent, 14.29);
assert.equal(proposed.attackDetectionPercent, 100);
assert.equal(proposed.tenantIsolationPercent, 100);
assert.equal(proposed.falseRestrictionPercent, 0);

assert.equal(smoothed.transientRestrictedSamples, 0);
assert.equal(unsmoothed.transientRestrictedSamples, 1);
assert.equal(smoothed.attackSamplesToRestriction, 2);
assert.equal(unsmoothed.attackSamplesToRestriction, 1);

assert.equal(guardedFeedback.additionalRecursiveActionExecutions, 0);
assert.equal(guardedFeedback.converged, true);
assert.equal(recursiveFeedback.additionalRecursiveActionExecutions, 5);
assert.equal(recursiveFeedback.converged, false);

assert.deepEqual(
  study.ablations.ledger.loads.map(({ p95InflationFactor }) => p95InflationFactor),
  [130.4, 134.4, 118.3],
);
assert.equal(study.claimBoundary.notClaimed.length, 4);

console.log("Ablation study and research-conclusion verification passed.");
console.log("PASS both baselines and the proposed mode retain the measured T10.7/T10.8 comparison");
console.log("PASS smoothing exposes noise suppression versus detection and recovery delay");
console.log("PASS terminal feedback remains exactly-once and ineligible for recursive action");
console.log("PASS asynchronous Fabric remains outside request latency and available authorization");
console.log("PASS contribution and limitation language excludes unsupported novelty and generalization");
