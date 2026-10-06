const SCORE_MINIMUM = 0;
const SCORE_MAXIMUM = 100;
const SOURCE_ID = /^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BAND_IDS = Object.freeze(["low", "medium", "high"]);
const BAND_SET = new Set(BAND_IDS);
const STATE_KEYS = new Set(["score", "band", "recoveryStreak"]);
const SOURCE_KEYS = new Set(["sourceId", "maximumInfluence", "corroboratingSourceIds"]);
const CRITICAL_KEYS = new Set(["kind", "componentId"]);

export const DEFAULT_TRUST_TRANSITION_CONFIGURATION = deepFreeze({
  bands: {
    low: { minimum: 0, baseMaximumExclusive: 40, recoveryThreshold: 45 },
    medium: {
      minimum: 40,
      baseMaximumExclusive: 70,
      deteriorationThreshold: 35,
      recoveryThreshold: 75,
    },
    high: { minimum: 70, maximum: 100, deteriorationThreshold: 65 },
  },
  recovery: {
    consecutiveQualifyingEvaluations: 2,
    distinctSourceCount: 2,
    maximumBandAdvancePerEvaluation: 1,
  },
  sourceInfluence: {
    interpretation: "maximum-absolute-score-delta-fraction",
    scoreRange: 100,
  },
});

export const CRITICAL_EVIDENCE_OVERRIDE_RULES = deepFreeze({
  "identity-compromised": {
    componentId: "identity",
    scoreCeiling: 20,
    forcedBand: "low",
  },
  "device-compromised": {
    componentId: "device",
    scoreCeiling: 20,
    forcedBand: "low",
  },
  "account-takeover-pattern": {
    componentId: "behaviour",
    scoreCeiling: 20,
    forcedBand: "low",
  },
  "certificate-revoked": {
    componentId: "certificate",
    scoreCeiling: 0,
    forcedBand: "low",
  },
  "blocking-compliance-breach": {
    componentId: "compliance",
    scoreCeiling: 20,
    forcedBand: "low",
  },
});

export const TRUST_TRANSITION_CONTROL_POLICY = deepFreeze({
  bandSemantics: "policy-input-not-authorization-outcome",
  deterioration: "immediate-at-lower-threshold-with-multi-band-drop",
  recovery: "consecutive-corroborated-evaluations-one-band-at-a-time",
  sourceInfluence: "accepted-receipt-cap-bounds-absolute-score-delta",
  criticalEvidence: "closed-negative-only-overrides-bypass-cap-downward",
  scoreDecimalPlaces: 2,
  roundingMode: "half-up",
});

export class TrustTransitionControlError extends Error {
  constructor(reasonCode) {
    super("Trust transition control input is invalid.");
    this.name = "TrustTransitionControlError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new TrustTransitionControlError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function validScore(value) {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= SCORE_MINIMUM
    && value <= SCORE_MAXIMUM;
}

function roundScore(value) {
  const factor = 10 ** TRUST_TRANSITION_CONTROL_POLICY.scoreDecimalPlaces;
  return Math.floor((value + Number.EPSILON) * factor + 0.5) / factor;
}

function classifyBaseBand(score) {
  if (score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.low.baseMaximumExclusive) return "low";
  if (score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.baseMaximumExclusive) return "medium";
  return "high";
}

function normalizePreviousState(value) {
  if (!hasExactKeys(value, STATE_KEYS)
    || !validScore(value.score)
    || !BAND_SET.has(value.band)
    || !Number.isSafeInteger(value.recoveryStreak)
    || value.recoveryStreak < 0
    || value.recoveryStreak >= DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations
    || (value.band === "high"
      && value.score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.high.deteriorationThreshold)
    || (value.band === "medium"
      && value.score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.deteriorationThreshold)
    || (value.recoveryStreak > 0
      && (value.band === "high" || value.score < recoveryThreshold(value.band)))) {
    fail("PREVIOUS_CONTROL_STATE_INVALID");
  }
  return Object.freeze({
    score: value.score,
    band: value.band,
    recoveryStreak: value.recoveryStreak,
  });
}

function normalizeSource(value) {
  if (!hasExactKeys(value, SOURCE_KEYS)
    || !SOURCE_ID.test(value.sourceId ?? "")
    || typeof value.maximumInfluence !== "number"
    || !Number.isFinite(value.maximumInfluence)
    || value.maximumInfluence <= 0
    || value.maximumInfluence > 1
    || !Array.isArray(value.corroboratingSourceIds)
    || !value.corroboratingSourceIds.every((sourceId) => SOURCE_ID.test(sourceId))) {
    fail("SOURCE_INFLUENCE_INVALID");
  }
  const sourceIds = Object.freeze([...new Set([value.sourceId, ...value.corroboratingSourceIds])].sort());
  return Object.freeze({
    sourceId: value.sourceId,
    maximumInfluence: value.maximumInfluence,
    corroboratingSourceIds: Object.freeze([...value.corroboratingSourceIds]),
    distinctSourceIds: sourceIds,
  });
}

function normalizeCriticalEvidence(value) {
  if (value === null || value === undefined) return null;
  if (!hasExactKeys(value, CRITICAL_KEYS)) fail("CRITICAL_EVIDENCE_INVALID");
  const rule = CRITICAL_EVIDENCE_OVERRIDE_RULES[value.kind];
  if (!rule || rule.componentId !== value.componentId) fail("CRITICAL_EVIDENCE_INVALID");
  return Object.freeze({ kind: value.kind, componentId: value.componentId, rule });
}

function deteriorationBand(previousBand, score) {
  if (score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.deteriorationThreshold) {
    return "low";
  }
  if (previousBand === "high"
    && score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.high.deteriorationThreshold) {
    return "medium";
  }
  return previousBand;
}

function nextRecoveryBand(previousBand) {
  if (previousBand === "low") return "medium";
  if (previousBand === "medium") return "high";
  return "high";
}

function recoveryThreshold(previousBand) {
  if (previousBand === "low") {
    return DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.low.recoveryThreshold;
  }
  if (previousBand === "medium") {
    return DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.recoveryThreshold;
  }
  return null;
}

export function initializeTrustControlState(score) {
  if (!validScore(score)) fail("INITIAL_CONTROL_SCORE_INVALID");
  return Object.freeze({ score, band: classifyBaseBand(score), recoveryStreak: 0 });
}

export function applyTrustTransitionControls({
  previousState: previousValue,
  candidateScore,
  source: sourceValue,
  criticalEvidence: criticalValue = null,
} = {}) {
  const previousState = normalizePreviousState(previousValue);
  if (!validScore(candidateScore)) fail("CANDIDATE_SCORE_INVALID");
  const source = normalizeSource(sourceValue);
  const criticalEvidence = normalizeCriticalEvidence(criticalValue);
  const requestedDelta = candidateScore - previousState.score;
  const maximumDeltaPoints = roundScore(
    source.maximumInfluence * DEFAULT_TRUST_TRANSITION_CONFIGURATION.sourceInfluence.scoreRange,
  );
  const boundedDelta = Math.max(-maximumDeltaPoints, Math.min(maximumDeltaPoints, requestedDelta));
  const boundedScore = roundScore(previousState.score + boundedDelta);

  if (criticalEvidence) {
    const score = roundScore(Math.min(
      previousState.score,
      candidateScore,
      criticalEvidence.rule.scoreCeiling,
    ));
    return deepFreeze({
      score,
      band: criticalEvidence.rule.forcedBand,
      transition: "critical-override",
      recoveryStreak: 0,
      state: { score, band: criticalEvidence.rule.forcedBand, recoveryStreak: 0 },
      sourceInfluence: {
        sourceId: source.sourceId,
        maximumInfluence: source.maximumInfluence,
        maximumDeltaPoints,
        requestedDelta: roundScore(requestedDelta),
        appliedDelta: roundScore(score - previousState.score),
        capped: false,
        bypassedForCriticalDeterioration: true,
      },
      recovery: {
        eligible: false,
        distinctSourceCount: source.distinctSourceIds.length,
        requiredDistinctSourceCount:
          DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.distinctSourceCount,
        qualifyingStreak: 0,
        requiredQualifyingStreak:
          DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations,
      },
      criticalOverride: {
        kind: criticalEvidence.kind,
        componentId: criticalEvidence.componentId,
        scoreCeiling: criticalEvidence.rule.scoreCeiling,
        forcedBand: criticalEvidence.rule.forcedBand,
      },
      policy: TRUST_TRANSITION_CONTROL_POLICY,
      configuration: DEFAULT_TRUST_TRANSITION_CONFIGURATION,
    });
  }

  const lowerBand = deteriorationBand(previousState.band, boundedScore);
  if (BAND_IDS.indexOf(lowerBand) < BAND_IDS.indexOf(previousState.band)) {
    return buildResult({
      previousState,
      source,
      candidateScore,
      requestedDelta,
      maximumDeltaPoints,
      boundedDelta,
      score: boundedScore,
      band: lowerBand,
      transition: "deteriorated",
      recoveryStreak: 0,
      recoveryEligible: false,
    });
  }

  const threshold = recoveryThreshold(previousState.band);
  const enoughSources = source.distinctSourceIds.length
    >= DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.distinctSourceCount;
  const recoveryEligible = threshold !== null && boundedScore >= threshold && enoughSources;
  const recoveryStreak = recoveryEligible ? previousState.recoveryStreak + 1 : 0;
  const recovered = recoveryStreak
    >= DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations;

  return buildResult({
    previousState,
    source,
    candidateScore,
    requestedDelta,
    maximumDeltaPoints,
    boundedDelta,
    score: boundedScore,
    band: recovered ? nextRecoveryBand(previousState.band) : previousState.band,
    transition: recovered ? "recovered" : "held",
    recoveryStreak: recovered ? 0 : recoveryStreak,
    recoveryEligible,
  });
}

function buildResult({
  previousState,
  source,
  requestedDelta,
  maximumDeltaPoints,
  boundedDelta,
  score,
  band,
  transition,
  recoveryStreak,
  recoveryEligible,
}) {
  return deepFreeze({
    score,
    band,
    transition,
    recoveryStreak,
    state: { score, band, recoveryStreak },
    sourceInfluence: {
      sourceId: source.sourceId,
      maximumInfluence: source.maximumInfluence,
      maximumDeltaPoints,
      requestedDelta: roundScore(requestedDelta),
      appliedDelta: roundScore(score - previousState.score),
      capped: Math.abs(requestedDelta) > maximumDeltaPoints,
      bypassedForCriticalDeterioration: false,
    },
    recovery: {
      eligible: recoveryEligible,
      distinctSourceCount: source.distinctSourceIds.length,
      requiredDistinctSourceCount:
        DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.distinctSourceCount,
      qualifyingStreak: recoveryStreak,
      requiredQualifyingStreak:
        DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations,
    },
    criticalOverride: null,
    policy: TRUST_TRANSITION_CONTROL_POLICY,
    configuration: DEFAULT_TRUST_TRANSITION_CONFIGURATION,
  });
}
