import assert from "node:assert/strict";
import {
  WEIGHTED_SCORE_METHOD,
  calculateWeightedTrustScore,
} from "../services/trust/src/index.mjs";

const baseline = calculateWeightedTrustScore({
  identity: 90,
  device: 80,
  behaviour: 70,
  certificate: 100,
  compliance: 60,
});
assert.equal(baseline.score, 79.5);
assert.equal(baseline.method, WEIGHTED_SCORE_METHOD);
assert.deepEqual(
  Object.values(baseline.contributions).map(({ weightedContribution }) => weightedContribution),
  [18, 20, 17.5, 15, 9],
);
console.log("PASS the default model matches the hand-calculated 79.50 score and contributions");

const tuned = calculateWeightedTrustScore(
  {
    identity: 20,
    device: 40,
    behaviour: 60,
    certificate: 80,
    compliance: 100,
  },
  {
    modelVersion: "1.1.0",
    weights: {
      identity: 0.10,
      device: 0.20,
      behaviour: 0.30,
      certificate: 0.25,
      compliance: 0.15,
    },
  },
);
assert.equal(tuned.score, 63);
assert.equal(tuned.modelVersion, "1.1.0");
console.log("PASS a complete tenant-tuned model matches an independent 63.00 calculation");

for (const value of [0, 100]) {
  const boundary = calculateWeightedTrustScore({
    identity: value,
    device: value,
    behaviour: value,
    certificate: value,
    compliance: value,
  });
  assert.equal(boundary.score, value);
}
console.log("PASS the weighted score preserves both normalized 0-100 boundaries");
