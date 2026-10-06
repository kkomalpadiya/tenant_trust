import assert from "node:assert/strict";
import { advanceSmoothedTrustScore } from "../services/trust/src/index.mjs";

const configuration = {
  initialScore: 60,
  smoothingAlpha: 0.30,
  staleAfterSeconds: 3600,
};

const first = advanceSmoothedTrustScore({
  configuration,
  observation: { score: 80, observedAt: "2026-10-06T08:00:00.000Z" },
  evaluatedAt: "2026-10-06T08:00:00.000Z",
});
assert.equal(first.score, 66);
console.log("PASS cold start applies 0.30 x 80 + 0.70 x 60 = 66.00");

const second = advanceSmoothedTrustScore({
  configuration,
  previousState: first.temporalState,
  observation: { score: 40, observedAt: "2026-10-06T08:10:00.000Z" },
  evaluatedAt: "2026-10-06T08:10:00.000Z",
});
assert.equal(second.score, 58.2);
console.log("PASS the next observation applies 0.30 x 40 + 0.70 x 66 = 58.20");

const decayed = advanceSmoothedTrustScore({
  configuration,
  previousState: first.temporalState,
  evaluatedAt: "2026-10-06T10:00:00.000Z",
});
assert.equal(decayed.score, 63);
assert.equal(decayed.calculation.retentionFactor, 0.5);
console.log("PASS one hour beyond staleness halves the distance from 66.00 to the 60.00 baseline");

const stale = advanceSmoothedTrustScore({
  configuration,
  previousState: first.temporalState,
  observation: { score: 100, observedAt: "2026-10-06T08:30:00.000Z" },
  evaluatedAt: "2026-10-06T10:00:00.000Z",
});
assert.equal(stale.score, 63);
assert.equal(stale.observationStatus, "stale");
console.log("PASS stale evidence is withheld and cannot refresh or increase the score");
