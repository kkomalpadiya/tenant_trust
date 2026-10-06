const SCORE_MINIMUM = 0;
const SCORE_MAXIMUM = 100;
const MAXIMUM_STALE_AFTER_SECONDS = 2_592_000;
const CONFIGURATION_KEYS = new Set(["initialScore", "smoothingAlpha", "staleAfterSeconds"]);
const STATE_KEYS = new Set(["score", "anchorScore", "lastFreshObservedAt", "lastEvaluatedAt"]);
const OBSERVATION_KEYS = new Set(["score", "observedAt"]);

export const TEMPORAL_SMOOTHING_POLICY = Object.freeze({
  method: "exponentially-weighted-average",
  coldStart: "configured-initial-score",
  missingBeforeStale: "hold",
  staleHandling: "withhold-observation",
  decayMethod: "exponential-toward-conservative-baseline",
  decayHalfLife: "stale-after-seconds",
  scoreDecimalPlaces: 2,
  roundingMode: "half-up",
});

export class TrustSmoothingError extends Error {
  constructor(reasonCode) {
    super("Temporal trust-score smoothing input is invalid.");
    this.name = "TrustSmoothingError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new TrustSmoothingError(reasonCode);
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value, expected) {
  return isPlainObject(value)
    && Object.keys(value).length === expected.size
    && Object.keys(value).every((key) => expected.has(key));
}

function validScore(value) {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= SCORE_MINIMUM
    && value <= SCORE_MAXIMUM;
}

function canonicalUtc(value) {
  if (typeof value !== "string" || !value.endsWith("Z")) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function roundScore(value) {
  const factor = 10 ** TEMPORAL_SMOOTHING_POLICY.scoreDecimalPlaces;
  return Math.floor((value + Number.EPSILON) * factor + 0.5) / factor;
}

function freezeState(score, anchorScore, lastFreshObservedAt, lastEvaluatedAt) {
  return Object.freeze({ score, anchorScore, lastFreshObservedAt, lastEvaluatedAt });
}

export function defineTemporalTrustConfiguration(value) {
  if (!hasExactKeys(value, CONFIGURATION_KEYS)
    || !validScore(value.initialScore)
    || typeof value.smoothingAlpha !== "number"
    || !Number.isFinite(value.smoothingAlpha)
    || value.smoothingAlpha <= 0
    || value.smoothingAlpha > 1
    || !Number.isSafeInteger(value.staleAfterSeconds)
    || value.staleAfterSeconds < 1
    || value.staleAfterSeconds > MAXIMUM_STALE_AFTER_SECONDS) {
    fail("TEMPORAL_CONFIGURATION_INVALID");
  }
  return Object.freeze({
    initialScore: value.initialScore,
    smoothingAlpha: value.smoothingAlpha,
    staleAfterSeconds: value.staleAfterSeconds,
  });
}

function normalizePreviousState(value, configuration, evaluatedAtMs) {
  if (value === null || value === undefined) return null;
  if (!hasExactKeys(value, STATE_KEYS)
    || !validScore(value.score)
    || !validScore(value.anchorScore)
    || (value.lastFreshObservedAt !== null && !canonicalUtc(value.lastFreshObservedAt))
    || !canonicalUtc(value.lastEvaluatedAt)) {
    fail("PREVIOUS_TEMPORAL_STATE_INVALID");
  }
  if (value.lastFreshObservedAt === null) {
    if (value.score !== configuration.initialScore || value.anchorScore !== configuration.initialScore) {
      fail("PREVIOUS_TEMPORAL_STATE_INVALID");
    }
  } else if (Date.parse(value.lastFreshObservedAt) > Date.parse(value.lastEvaluatedAt)) {
    fail("PREVIOUS_TEMPORAL_STATE_INVALID");
  }
  if (Date.parse(value.lastEvaluatedAt) > evaluatedAtMs) {
    fail("PREVIOUS_TEMPORAL_STATE_INVALID");
  }
  return Object.freeze({
    score: value.score,
    anchorScore: value.anchorScore,
    lastFreshObservedAt: value.lastFreshObservedAt,
    lastEvaluatedAt: value.lastEvaluatedAt,
  });
}

function normalizeObservation(value, evaluatedAtMs) {
  if (value === null || value === undefined) return null;
  if (!hasExactKeys(value, OBSERVATION_KEYS)
    || !validScore(value.score)
    || !canonicalUtc(value.observedAt)
    || Date.parse(value.observedAt) > evaluatedAtMs) {
    fail("TRUST_OBSERVATION_INVALID");
  }
  return Object.freeze({ score: value.score, observedAt: value.observedAt });
}

function result({
  score,
  phase,
  observationStatus,
  evaluatedAt,
  configuration,
  previousScore,
  observationScore,
  temporalState,
  calculation,
}) {
  return Object.freeze({
    score,
    phase,
    observationStatus,
    evaluatedAt,
    configuration,
    previousScore,
    observationScore,
    temporalState,
    calculation: Object.freeze(calculation),
    policy: TEMPORAL_SMOOTHING_POLICY,
  });
}

export function advanceSmoothedTrustScore({
  configuration: configurationValue,
  previousState: previousValue = null,
  observation: observationValue = null,
  evaluatedAt,
} = {}) {
  if (!canonicalUtc(evaluatedAt)) fail("EVALUATION_TIME_INVALID");
  const evaluatedAtMs = Date.parse(evaluatedAt);
  const configuration = defineTemporalTrustConfiguration(configurationValue);
  const previousState = normalizePreviousState(previousValue, configuration, evaluatedAtMs);
  const observation = normalizeObservation(observationValue, evaluatedAtMs);
  const observationAgeSeconds = observation
    ? (evaluatedAtMs - Date.parse(observation.observedAt)) / 1000
    : null;
  const observationStatus = observation === null
    ? "missing"
    : observationAgeSeconds > configuration.staleAfterSeconds ? "stale" : "fresh";

  if (observationStatus === "fresh") {
    if (previousState?.lastFreshObservedAt
      && Date.parse(observation.observedAt) <= Date.parse(previousState.lastFreshObservedAt)) {
      fail("TRUST_OBSERVATION_NOT_NEWER");
    }
    const priorScore = previousState?.score ?? configuration.initialScore;
    const score = roundScore(
      configuration.smoothingAlpha * observation.score
      + (1 - configuration.smoothingAlpha) * priorScore,
    );
    const temporalState = freezeState(score, score, observation.observedAt, evaluatedAt);
    return result({
      score,
      phase: previousState?.lastFreshObservedAt == null ? "initialized" : "updated",
      observationStatus,
      evaluatedAt,
      configuration,
      previousScore: previousState?.score ?? null,
      observationScore: observation.score,
      temporalState,
      calculation: {
        kind: "ewa",
        priorScore,
        observationScore: observation.score,
        alpha: configuration.smoothingAlpha,
        retainedWeight: 1 - configuration.smoothingAlpha,
        observationAgeSeconds,
      },
    });
  }

  if (previousState === null || previousState.lastFreshObservedAt === null) {
    const score = configuration.initialScore;
    return result({
      score,
      phase: "cold-start",
      observationStatus,
      evaluatedAt,
      configuration,
      previousScore: previousState?.score ?? null,
      observationScore: observation?.score ?? null,
      temporalState: freezeState(score, score, null, evaluatedAt),
      calculation: {
        kind: "initial-score",
        initialScore: configuration.initialScore,
        observationAgeSeconds,
      },
    });
  }

  const ageSinceFreshSeconds = (
    evaluatedAtMs - Date.parse(previousState.lastFreshObservedAt)
  ) / 1000;
  const elapsedBeyondStaleSeconds = Math.max(
    0,
    ageSinceFreshSeconds - configuration.staleAfterSeconds,
  );
  if (elapsedBeyondStaleSeconds === 0) {
    return result({
      score: previousState.score,
      phase: "held",
      observationStatus,
      evaluatedAt,
      configuration,
      previousScore: previousState.score,
      observationScore: observation?.score ?? null,
      temporalState: freezeState(
        previousState.score,
        previousState.anchorScore,
        previousState.lastFreshObservedAt,
        evaluatedAt,
      ),
      calculation: {
        kind: "hold",
        ageSinceFreshSeconds,
        staleAfterSeconds: configuration.staleAfterSeconds,
        observationAgeSeconds,
      },
    });
  }

  const baselineScore = Math.min(configuration.initialScore, previousState.anchorScore);
  const retentionFactor = 2 ** (
    -elapsedBeyondStaleSeconds / configuration.staleAfterSeconds
  );
  const score = roundScore(
    baselineScore + (previousState.anchorScore - baselineScore) * retentionFactor,
  );
  return result({
    score,
    phase: "decayed",
    observationStatus,
    evaluatedAt,
    configuration,
    previousScore: previousState.score,
    observationScore: observation?.score ?? null,
    temporalState: freezeState(
      score,
      previousState.anchorScore,
      previousState.lastFreshObservedAt,
      evaluatedAt,
    ),
    calculation: {
      kind: "exponential-decay",
      baselineScore,
      anchorScore: previousState.anchorScore,
      ageSinceFreshSeconds,
      elapsedBeyondStaleSeconds,
      halfLifeSeconds: configuration.staleAfterSeconds,
      retentionFactor: Number(retentionFactor.toFixed(12)),
      observationAgeSeconds,
    },
  });
}
