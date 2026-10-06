import assert from "node:assert/strict";
import {
  applyTrustTransitionControls,
  initializeTrustControlState,
} from "@tenant-trust/trust";

const SOURCE_A = "src_018f1234-5678-7abc-8def-0123456789e0";
const SOURCE_B = "src_018f1234-5678-7abc-8def-0123456789e1";
const source = (maximumInfluence, corroboratingSourceIds = []) => ({
  sourceId: SOURCE_A,
  maximumInfluence,
  corroboratingSourceIds,
});

const capped = applyTrustTransitionControls({
  previousState: initializeTrustControlState(60),
  candidateScore: 100,
  source: source(0.10),
});
assert.equal(capped.score, 70);
assert.equal(capped.band, "medium");
assert.equal(capped.recoveryStreak, 0);

const firstRecovery = applyTrustTransitionControls({
  previousState: capped.state,
  candidateScore: 90,
  source: source(1, [SOURCE_B]),
});
const recovered = applyTrustTransitionControls({
  previousState: firstRecovery.state,
  candidateScore: 90,
  source: source(1, [SOURCE_B]),
});
assert.equal(firstRecovery.band, "medium");
assert.equal(recovered.band, "high");

const deteriorated = applyTrustTransitionControls({
  previousState: recovered.state,
  candidateScore: 64.99,
  source: source(1),
});
assert.equal(deteriorated.band, "medium");

const revoked = applyTrustTransitionControls({
  previousState: initializeTrustControlState(95),
  candidateScore: 95,
  source: source(0.0001),
  criticalEvidence: { kind: "certificate-revoked", componentId: "certificate" },
});
assert.equal(revoked.score, 0);
assert.equal(revoked.band, "low");

console.log("PASS source influence bounds a single observation's score movement");
console.log("PASS hysteresis and corroborated recovery prevent band oscillation and score farming");
console.log("PASS critical negative evidence follows closed downward-only override rules");
