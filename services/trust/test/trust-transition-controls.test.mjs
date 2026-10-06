import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CRITICAL_EVIDENCE_OVERRIDE_RULES,
  DEFAULT_TRUST_TRANSITION_CONFIGURATION,
  TRUST_TRANSITION_CONTROL_POLICY,
  TrustTransitionControlError,
  applyTrustTransitionControls,
  initializeTrustControlState,
} from "../src/index.mjs";

const SOURCE_A = "src_018f1234-5678-7abc-8def-0123456789e0";
const SOURCE_B = "src_018f1234-5678-7abc-8def-0123456789e1";

function source(maximumInfluence = 1, corroboratingSourceIds = []) {
  return { sourceId: SOURCE_A, maximumInfluence, corroboratingSourceIds };
}

test("initializes low, medium and high bands at explicit decimal boundaries", () => {
  assert.deepEqual(initializeTrustControlState(39.99), {
    score: 39.99,
    band: "low",
    recoveryStreak: 0,
  });
  assert.equal(initializeTrustControlState(40).band, "medium");
  assert.equal(initializeTrustControlState(69.99).band, "medium");
  assert.equal(initializeTrustControlState(70).band, "high");
});

test("caps an upward score change using the accepted source influence fraction", () => {
  const output = applyTrustTransitionControls({
    previousState: initializeTrustControlState(50),
    candidateScore: 100,
    source: source(0.10),
  });

  assert.equal(output.score, 60);
  assert.equal(output.band, "medium");
  assert.equal(output.sourceInfluence.maximumDeltaPoints, 10);
  assert.equal(output.sourceInfluence.requestedDelta, 50);
  assert.equal(output.sourceInfluence.appliedDelta, 10);
  assert.equal(output.sourceInfluence.capped, true);
});

test("applies the same source cap to non-critical deterioration", () => {
  const output = applyTrustTransitionControls({
    previousState: initializeTrustControlState(80),
    candidateScore: 0,
    source: source(0.05),
  });

  assert.equal(output.score, 75);
  assert.equal(output.band, "high");
  assert.equal(output.transition, "held");
  assert.equal(output.sourceInfluence.appliedDelta, -5);
});

test("uses hysteresis to prevent band flapping around the base boundaries", () => {
  const high = applyTrustTransitionControls({
    previousState: initializeTrustControlState(72),
    candidateScore: 69,
    source: source(),
  });
  const medium = applyTrustTransitionControls({
    previousState: initializeTrustControlState(68),
    candidateScore: 72,
    source: source(1, [SOURCE_B]),
  });

  assert.equal(high.band, "high");
  assert.equal(high.transition, "held");
  assert.equal(medium.band, "medium");
  assert.equal(medium.recoveryStreak, 0);
});

test("deteriorates immediately and can skip directly to low", () => {
  const medium = applyTrustTransitionControls({
    previousState: initializeTrustControlState(80),
    candidateScore: 64.99,
    source: source(),
  });
  const low = applyTrustTransitionControls({
    previousState: initializeTrustControlState(80),
    candidateScore: 34.99,
    source: source(),
  });

  assert.equal(medium.band, "medium");
  assert.equal(medium.transition, "deteriorated");
  assert.equal(low.band, "low");
  assert.equal(low.transition, "deteriorated");
});

test("treats deterioration and recovery thresholds as exact inclusive boundaries", () => {
  const highAtFloor = applyTrustTransitionControls({
    previousState: initializeTrustControlState(80),
    candidateScore: 65,
    source: source(),
  });
  const mediumAtFloor = applyTrustTransitionControls({
    previousState: initializeTrustControlState(50),
    candidateScore: 35,
    source: source(),
  });
  const lowRecovery = applyTrustTransitionControls({
    previousState: initializeTrustControlState(20),
    candidateScore: 45,
    source: source(1, [SOURCE_B]),
  });
  const mediumRecovery = applyTrustTransitionControls({
    previousState: initializeTrustControlState(50),
    candidateScore: 75,
    source: source(1, [SOURCE_B]),
  });

  assert.equal(highAtFloor.band, "high");
  assert.equal(mediumAtFloor.band, "medium");
  assert.equal(lowRecovery.recoveryStreak, 1);
  assert.equal(mediumRecovery.recoveryStreak, 1);
});

test("requires two distinct sources and two consecutive evaluations for recovery", () => {
  const previous = initializeTrustControlState(60);
  const uncorroborated = applyTrustTransitionControls({
    previousState: previous,
    candidateScore: 90,
    source: source(),
  });
  const first = applyTrustTransitionControls({
    previousState: uncorroborated.state,
    candidateScore: 90,
    source: source(1, [SOURCE_B]),
  });
  const second = applyTrustTransitionControls({
    previousState: first.state,
    candidateScore: 90,
    source: source(1, [SOURCE_B]),
  });

  assert.equal(uncorroborated.band, "medium");
  assert.equal(uncorroborated.recoveryStreak, 0);
  assert.equal(first.band, "medium");
  assert.equal(first.recoveryStreak, 1);
  assert.equal(second.band, "high");
  assert.equal(second.transition, "recovered");
  assert.equal(second.recoveryStreak, 0);
});

test("resets a recovery streak when either score or corroboration stops qualifying", () => {
  const first = applyTrustTransitionControls({
    previousState: initializeTrustControlState(60),
    candidateScore: 80,
    source: source(1, [SOURCE_B]),
  });
  const reset = applyTrustTransitionControls({
    previousState: first.state,
    candidateScore: 74.99,
    source: source(1, [SOURCE_B]),
  });

  assert.equal(first.recoveryStreak, 1);
  assert.equal(reset.band, "medium");
  assert.equal(reset.recoveryStreak, 0);
});

test("advances recovery by at most one band per evaluation", () => {
  const first = applyTrustTransitionControls({
    previousState: initializeTrustControlState(20),
    candidateScore: 100,
    source: source(1, [SOURCE_B]),
  });
  const second = applyTrustTransitionControls({
    previousState: first.state,
    candidateScore: 100,
    source: source(1, [SOURCE_B]),
  });

  assert.equal(first.band, "low");
  assert.equal(first.recoveryStreak, 1);
  assert.equal(second.band, "medium");
  assert.equal(second.transition, "recovered");
});

test("critical certificate revocation bypasses the source cap only to reduce trust", () => {
  const output = applyTrustTransitionControls({
    previousState: initializeTrustControlState(90),
    candidateScore: 90,
    source: source(0.0001),
    criticalEvidence: { kind: "certificate-revoked", componentId: "certificate" },
  });

  assert.equal(output.score, 0);
  assert.equal(output.band, "low");
  assert.equal(output.transition, "critical-override");
  assert.equal(output.sourceInfluence.bypassedForCriticalDeterioration, true);
  assert.equal(output.criticalOverride.scoreCeiling, 0);
});

test("a critical override never improves an already lower score", () => {
  const output = applyTrustTransitionControls({
    previousState: initializeTrustControlState(10),
    candidateScore: 90,
    source: source(0.10),
    criticalEvidence: { kind: "device-compromised", componentId: "device" },
  });

  assert.equal(output.score, 10);
  assert.equal(output.band, "low");
});

test("rejects unknown, mismatched and caller-defined critical overrides", () => {
  for (const criticalEvidence of [
    { kind: "positive-override", componentId: "identity" },
    { kind: "certificate-revoked", componentId: "device" },
    { kind: "identity-compromised", componentId: "identity", scoreCeiling: 100 },
  ]) {
    assert.throws(
      () => applyTrustTransitionControls({
        previousState: initializeTrustControlState(50),
        candidateScore: 100,
        source: source(),
        criticalEvidence,
      }),
      (error) => error instanceof TrustTransitionControlError,
    );
  }
});

test("fails closed on malformed state, score and source influence inputs", () => {
  for (const operation of [
    () => initializeTrustControlState(Number.NaN),
    () => initializeTrustControlState(100.01),
    () => applyTrustTransitionControls({
      previousState: { score: 50, band: "medium", recoveryStreak: 2 },
      candidateScore: 60,
      source: source(),
    }),
    () => applyTrustTransitionControls({
      previousState: { score: 64.99, band: "high", recoveryStreak: 0 },
      candidateScore: 70,
      source: source(),
    }),
    () => applyTrustTransitionControls({
      previousState: initializeTrustControlState(50),
      candidateScore: -1,
      source: source(),
    }),
    () => applyTrustTransitionControls({
      previousState: initializeTrustControlState(50),
      candidateScore: 60,
      source: source(0),
    }),
    () => applyTrustTransitionControls({
      previousState: initializeTrustControlState(50),
      candidateScore: 60,
      source: { ...source(), corroboratingSourceIds: ["src_invalid"] },
    }),
  ]) {
    assert.throws(operation, (error) => error instanceof TrustTransitionControlError);
  }
});

test("returns deeply immutable rules, state and explanations", () => {
  const output = applyTrustTransitionControls({
    previousState: initializeTrustControlState(50),
    candidateScore: 55,
    source: source(0.10, [SOURCE_B]),
  });

  assert.ok(Object.isFrozen(DEFAULT_TRUST_TRANSITION_CONFIGURATION));
  assert.ok(Object.isFrozen(DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands));
  assert.ok(Object.isFrozen(CRITICAL_EVIDENCE_OVERRIDE_RULES));
  assert.ok(Object.isFrozen(TRUST_TRANSITION_CONTROL_POLICY));
  assert.ok(Object.isFrozen(output));
  assert.ok(Object.isFrozen(output.state));
  assert.ok(Object.isFrozen(output.sourceInfluence));
  assert.ok(Object.isFrozen(output.recovery));
});
