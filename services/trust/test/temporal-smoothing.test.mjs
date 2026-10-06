import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TEMPORAL_SMOOTHING_POLICY,
  TrustSmoothingError,
  advanceSmoothedTrustScore,
  defineTemporalTrustConfiguration,
} from "../src/index.mjs";

const configuration = Object.freeze({
  initialScore: 60,
  smoothingAlpha: 0.30,
  staleAfterSeconds: 3600,
});

test("defines one immutable bounded temporal configuration", () => {
  const defined = defineTemporalTrustConfiguration(configuration);
  assert.deepEqual(defined, configuration);
  assert.ok(Object.isFrozen(defined));
});

test("uses the configured initial score when no evidence has ever been observed", () => {
  const output = advanceSmoothedTrustScore({
    configuration,
    evaluatedAt: "2026-10-06T08:00:00.000Z",
  });

  assert.equal(output.score, 60);
  assert.equal(output.phase, "cold-start");
  assert.equal(output.observationStatus, "missing");
  assert.deepEqual(output.temporalState, {
    score: 60,
    anchorScore: 60,
    lastFreshObservedAt: null,
    lastEvaluatedAt: "2026-10-06T08:00:00.000Z",
  });
});

test("initializes a fresh observation by smoothing it against the configured initial score", () => {
  const output = advanceSmoothedTrustScore({
    configuration,
    observation: { score: 80, observedAt: "2026-10-06T08:00:00.000Z" },
    evaluatedAt: "2026-10-06T08:00:30.000Z",
  });

  assert.equal(output.score, 66);
  assert.equal(output.phase, "initialized");
  assert.equal(output.observationStatus, "fresh");
  assert.deepEqual(output.calculation, {
    kind: "ewa",
    priorScore: 60,
    observationScore: 80,
    alpha: 0.30,
    retainedWeight: 0.70,
    observationAgeSeconds: 30,
  });
});

test("matches a multi-observation EWA calculation", () => {
  const first = advanceSmoothedTrustScore({
    configuration,
    observation: { score: 80, observedAt: "2026-10-06T08:00:00.000Z" },
    evaluatedAt: "2026-10-06T08:00:00.000Z",
  });
  const second = advanceSmoothedTrustScore({
    configuration,
    previousState: first.temporalState,
    observation: { score: 40, observedAt: "2026-10-06T08:10:00.000Z" },
    evaluatedAt: "2026-10-06T08:10:00.000Z",
  });

  assert.equal(first.score, 66);
  assert.equal(second.score, 58.2);
  assert.equal(second.phase, "updated");
  assert.equal(second.calculation.priorScore, 66);
});

test("treats the first fresh observation after a stored cold start as initialization", () => {
  const coldStart = advanceSmoothedTrustScore({
    configuration,
    evaluatedAt: "2026-10-06T08:00:00.000Z",
  });
  const initialized = advanceSmoothedTrustScore({
    configuration,
    previousState: coldStart.temporalState,
    observation: { score: 80, observedAt: "2026-10-06T08:05:00.000Z" },
    evaluatedAt: "2026-10-06T08:05:00.000Z",
  });

  assert.equal(initialized.phase, "initialized");
  assert.equal(initialized.score, 66);
});

test("holds the last score when evidence is missing but the last observation is still fresh", () => {
  const output = advanceSmoothedTrustScore({
    configuration,
    previousState: {
      score: 66,
      anchorScore: 66,
      lastFreshObservedAt: "2026-10-06T08:00:00.000Z",
      lastEvaluatedAt: "2026-10-06T08:00:00.000Z",
    },
    observation: null,
    evaluatedAt: "2026-10-06T08:45:00.000Z",
  });

  assert.equal(output.score, 66);
  assert.equal(output.phase, "held");
  assert.equal(output.calculation.kind, "hold");
});

test("decays stale trust toward the conservative baseline by one half-life per stale window", () => {
  const previousState = {
    score: 66,
    anchorScore: 66,
    lastFreshObservedAt: "2026-10-06T08:00:00.000Z",
    lastEvaluatedAt: "2026-10-06T08:00:00.000Z",
  };
  const oneHalfLife = advanceSmoothedTrustScore({
    configuration,
    previousState,
    evaluatedAt: "2026-10-06T10:00:00.000Z",
  });
  const twoHalfLives = advanceSmoothedTrustScore({
    configuration,
    previousState: oneHalfLife.temporalState,
    evaluatedAt: "2026-10-06T11:00:00.000Z",
  });

  assert.equal(oneHalfLife.score, 63);
  assert.equal(twoHalfLives.score, 61.5);
  assert.equal(oneHalfLife.calculation.retentionFactor, 0.5);
  assert.equal(twoHalfLives.calculation.retentionFactor, 0.25);
  assert.equal(twoHalfLives.temporalState.anchorScore, 66);
});

test("withholds a stale observation instead of applying it", () => {
  const output = advanceSmoothedTrustScore({
    configuration,
    previousState: {
      score: 66,
      anchorScore: 66,
      lastFreshObservedAt: "2026-10-06T08:00:00.000Z",
      lastEvaluatedAt: "2026-10-06T08:00:00.000Z",
    },
    observation: { score: 100, observedAt: "2026-10-06T08:30:00.000Z" },
    evaluatedAt: "2026-10-06T10:00:00.000Z",
  });

  assert.equal(output.observationStatus, "stale");
  assert.equal(output.phase, "decayed");
  assert.equal(output.score, 63);
  assert.equal(output.observationScore, 100);
});

test("missing evidence never improves a score below the configured initial score", () => {
  const output = advanceSmoothedTrustScore({
    configuration,
    previousState: {
      score: 40,
      anchorScore: 40,
      lastFreshObservedAt: "2026-10-06T08:00:00.000Z",
      lastEvaluatedAt: "2026-10-06T08:00:00.000Z",
    },
    evaluatedAt: "2026-10-06T12:00:00.000Z",
  });

  assert.equal(output.score, 40);
  assert.equal(output.calculation.baselineScore, 40);
});

test("supports alpha one and preserves the normalized score boundaries", () => {
  const immediate = { ...configuration, smoothingAlpha: 1 };
  for (const score of [0, 100]) {
    const output = advanceSmoothedTrustScore({
      configuration: immediate,
      observation: { score, observedAt: "2026-10-06T08:00:00.000Z" },
      evaluatedAt: "2026-10-06T08:00:00.000Z",
    });
    assert.equal(output.score, score);
  }
});

test("returns a deeply immutable explanation and policy", () => {
  const output = advanceSmoothedTrustScore({
    configuration,
    observation: { score: 80, observedAt: "2026-10-06T08:00:00.000Z" },
    evaluatedAt: "2026-10-06T08:00:00.000Z",
  });

  assert.equal(output.policy, TEMPORAL_SMOOTHING_POLICY);
  assert.ok(Object.isFrozen(output));
  assert.ok(Object.isFrozen(output.configuration));
  assert.ok(Object.isFrozen(output.temporalState));
  assert.ok(Object.isFrozen(output.calculation));
  assert.ok(Object.isFrozen(output.policy));
});

test("fails closed on malformed configuration, state, times and reordered fresh evidence", () => {
  for (const operation of [
    () => defineTemporalTrustConfiguration({ ...configuration, smoothingAlpha: 0 }),
    () => defineTemporalTrustConfiguration({ ...configuration, smoothingAlpha: 1.01 }),
    () => defineTemporalTrustConfiguration({ ...configuration, staleAfterSeconds: 0 }),
    () => defineTemporalTrustConfiguration({ ...configuration, initialScore: 101 }),
    () => advanceSmoothedTrustScore({ configuration, evaluatedAt: "2026-10-06 08:00:00" }),
    () => advanceSmoothedTrustScore({
      configuration,
      observation: { score: 50, observedAt: "2026-10-06T08:01:00.000Z" },
      evaluatedAt: "2026-10-06T08:00:00.000Z",
    }),
    () => advanceSmoothedTrustScore({
      configuration,
      previousState: {
        score: 60,
        anchorScore: 60,
        lastFreshObservedAt: null,
        lastEvaluatedAt: "2026-10-06T08:00:00.000Z",
        extra: true,
      },
      evaluatedAt: "2026-10-06T08:00:00.000Z",
    }),
    () => advanceSmoothedTrustScore({
      configuration,
      previousState: {
        score: 66,
        anchorScore: 66,
        lastFreshObservedAt: "2026-10-06T08:10:00.000Z",
        lastEvaluatedAt: "2026-10-06T08:10:00.000Z",
      },
      observation: { score: 70, observedAt: "2026-10-06T08:05:00.000Z" },
      evaluatedAt: "2026-10-06T08:15:00.000Z",
    }),
    () => advanceSmoothedTrustScore({
      configuration,
      previousState: {
        score: 66,
        anchorScore: 66,
        lastFreshObservedAt: "2026-10-06T08:00:00.000Z",
        lastEvaluatedAt: "2026-10-06T09:00:00.000Z",
      },
      evaluatedAt: "2026-10-06T08:59:59.000Z",
    }),
  ]) {
    assert.throws(operation, (error) => error instanceof TrustSmoothingError);
  }
});
