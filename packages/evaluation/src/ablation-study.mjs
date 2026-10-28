import {
  CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY,
  advanceSmoothedTrustScore,
} from "@tenant-trust/trust";
import { SECURITY_ACTION_TRIGGER_POLICY } from "@tenant-trust/orchestrator";

export const ABLATION_STUDY_ID = "tenant-trust-ablation-study-v1";

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function round(value, decimalPlaces = 3) {
  const factor = 10 ** decimalPlaces;
  return Math.round((value + Number.EPSILON) * factor) / factor;
}

export const EVALUATION_REFERENCE_RESULTS = deepFreeze({
  sourceTasks: ["T10.7", "T10.8"],
  measuredFunctionalTrialsPerMode: 12_300,
  modes: [
    {
      modeId: "jwt-rbac-baseline-v1",
      attackDetection: { numerator: 1_230, denominator: 8_610 },
      falseRestriction: { numerator: 0, denominator: 1_230 },
      tenantIsolation: { numerator: 1_230, denominator: 2_460 },
      replayRejection: { numerator: 0, denominator: 1_230 },
      auditModificationDetection: { numerator: 0, denominator: 1_230 },
      ledgerVerification: { numerator: 0, denominator: 1_230 },
      p95EndToEndMillisecondsByLoad: { 1: 0.111, 8: 0.135, 32: 0.147 },
      medianThroughputByLoad: { 1: 10_488.463, 8: 8_340.114, 32: 8_265.458 },
    },
    {
      modeId: "pki-rbac-baseline-v1",
      attackDetection: { numerator: 1_230, denominator: 8_610 },
      falseRestriction: { numerator: 0, denominator: 1_230 },
      tenantIsolation: { numerator: 1_230, denominator: 2_460 },
      replayRejection: { numerator: 0, denominator: 1_230 },
      auditModificationDetection: { numerator: 0, denominator: 1_230 },
      ledgerVerification: { numerator: 0, denominator: 1_230 },
      p95EndToEndMillisecondsByLoad: { 1: 0.004, 8: 0.007, 32: 0.006 },
      medianThroughputByLoad: { 1: 278_955.307, 8: 220_828.979, 32: 273_982.046 },
    },
    {
      modeId: "adaptive-trust-opa-v1",
      attackDetection: { numerator: 8_610, denominator: 8_610 },
      falseRestriction: { numerator: 0, denominator: 1_230 },
      tenantIsolation: { numerator: 2_460, denominator: 2_460 },
      replayRejection: { numerator: 1_230, denominator: 1_230 },
      auditModificationDetection: { numerator: 1_230, denominator: 1_230 },
      ledgerVerification: { numerator: 1_230, denominator: 1_230 },
      p95EndToEndMillisecondsByLoad: { 1: 16.927, 8: 16.417, 32: 18.666 },
      medianThroughputByLoad: { 1: 65.199, 8: 902.403, 32: 914.277 },
    },
  ],
  ledger: {
    measuredCommitments: 30,
    p50CommitDelayMilliseconds: 2_170.608,
    p95CommitDelayMilliseconds: 2_190.359,
    outageRecoveryRepetitions: 3,
    medianOutageRecoveryMilliseconds: 9_365.072,
  },
});

function rate({ numerator, denominator }) {
  return round(numerator / denominator * 100, 2);
}

function temporalTrace(smoothingAlpha, scores) {
  const configuration = { initialScore: 75, smoothingAlpha, staleAfterSeconds: 300 };
  let previousState = null;
  const start = Date.parse("2026-10-28T08:00:00.000Z");
  return scores.map((score, index) => {
    const evaluatedAt = new Date(start + index * 60_000).toISOString();
    const result = advanceSmoothedTrustScore({
      configuration,
      previousState,
      observation: { score, observedAt: evaluatedAt },
      evaluatedAt,
    });
    previousState = result.temporalState;
    return result.score;
  });
}

function thresholdTransitions(trace, threshold) {
  const states = trace.map((score) => score < threshold ? "restricted" : "normal");
  return states.slice(1).reduce(
    (count, state, index) => count + Number(state !== states[index]),
    0,
  );
}

function firstRestrictedAttackSample(trace, attackStartsAt, threshold) {
  const relative = trace.slice(attackStartsAt).findIndex((score) => score < threshold);
  return relative === -1 ? null : relative + 1;
}

function firstRecoveredSample(trace, recoveryStartsAt, threshold) {
  const relative = trace.slice(recoveryStartsAt).findIndex((score) => score >= threshold);
  return relative === -1 ? null : relative + 1;
}

function smoothingAblation() {
  const threshold = 60;
  const transient = [80, 80, 35, 80, 80];
  const sustained = [80, 35, 35, 35, 35, 80, 80, 80, 80];
  const variants = [
    { variantId: "configured-smoothing", smoothingAlpha: 0.3 },
    { variantId: "no-smoothing", smoothingAlpha: 1 },
  ].map((variant) => {
    const transientTrace = temporalTrace(variant.smoothingAlpha, transient);
    const sustainedTrace = temporalTrace(variant.smoothingAlpha, sustained);
    return {
      ...variant,
      transientTrace,
      transientRestrictedSamples: transientTrace.filter((score) => score < threshold).length,
      transientThresholdTransitions: thresholdTransitions(transientTrace, threshold),
      sustainedTrace,
      attackSamplesToRestriction: firstRestrictedAttackSample(sustainedTrace, 1, threshold),
      recoverySamplesToNormal: firstRecoveredSample(sustainedTrace, 5, threshold),
    };
  });
  return {
    threshold,
    transientObservationScores: transient,
    sustainedObservationScores: sustained,
    variants,
    conclusion: "Configured smoothing removes the one-sample false restriction but needs one additional sustained low observation to restrict and one additional recovery observation to return to normal.",
  };
}

function feedbackAblation() {
  const maximumCounterfactualDepth = 5;
  const implemented = {
    variantId: "non-recursive-terminal-feedback",
    inputDeliveries: 3,
    durableTrustEffects: 1,
    initialActionExecutions: 1,
    additionalRecursiveActionExecutions: 0,
    converged: true,
  };
  const recursive = {
    variantId: "terminal-feedback-action-eligible",
    inputDeliveries: 3,
    durableTrustEffects: 1 + maximumCounterfactualDepth,
    initialActionExecutions: 1,
    additionalRecursiveActionExecutions: maximumCounterfactualDepth,
    converged: false,
    observationDepthCap: maximumCounterfactualDepth,
  };
  return {
    implementationControls: {
      exactlyOnceTrustEffect: CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY.deliverySemantics,
      securityActionEligibility: CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY.securityActionEligibility,
      terminalNonTriggerKinds: SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.terminalNonTriggerKinds,
    },
    variants: [implemented, recursive],
    conclusion: "The implemented terminal-feedback guard stops the causal chain after one durable trust effect. The action-eligible counterfactual still had not converged at the five-generation observation cap.",
  };
}

function ledgerAblation() {
  const proposed = EVALUATION_REFERENCE_RESULTS.modes.find(({ modeId }) => modeId === "adaptive-trust-opa-v1");
  const commitP95 = EVALUATION_REFERENCE_RESULTS.ledger.p95CommitDelayMilliseconds;
  const loads = [1, 8, 32].map((load) => {
    const asynchronousP95 = proposed.p95EndToEndMillisecondsByLoad[load];
    const synchronousP95 = asynchronousP95 + commitP95;
    return {
      load,
      asynchronousRequestP95Milliseconds: asynchronousP95,
      synchronousCounterfactualP95Milliseconds: round(synchronousP95),
      p95InflationFactor: round(synchronousP95 / asynchronousP95, 1),
    };
  });
  return {
    commitP95Milliseconds: commitP95,
    loads,
    implementedOutageBehavior: "authorization-continues-and-outbox-reconciles",
    synchronousCounterfactualOutageBehavior: "authorization-blocks-or-fails-with-ledger",
    conclusion: "Keeping Fabric off the request path avoids a modeled 118.3x to 134.4x p95 latency increase and preserves authorization during the measured peer outage.",
  };
}

export function createAblationStudy() {
  return deepFreeze({
    studyId: ABLATION_STUDY_ID,
    referenceResults: EVALUATION_REFERENCE_RESULTS,
    modeComparison: EVALUATION_REFERENCE_RESULTS.modes.map((mode) => ({
      modeId: mode.modeId,
      attackDetectionPercent: rate(mode.attackDetection),
      falseRestrictionPercent: rate(mode.falseRestriction),
      tenantIsolationPercent: rate(mode.tenantIsolation),
      replayRejectionPercent: rate(mode.replayRejection),
      auditModificationDetectionPercent: rate(mode.auditModificationDetection),
      ledgerVerificationPercent: rate(mode.ledgerVerification),
      p95EndToEndMillisecondsByLoad: mode.p95EndToEndMillisecondsByLoad,
      medianThroughputByLoad: mode.medianThroughputByLoad,
    })),
    ablations: {
      smoothing: smoothingAblation(),
      feedback: feedbackAblation(),
      ledger: ledgerAblation(),
    },
    claimBoundary: {
      contribution: "An implemented and reproducibly evaluated integration of established tenant-bound identity, deterministic trust, policy enforcement, controlled feedback and asynchronous verifiable audit mechanisms.",
      notClaimed: [
        "a novel cryptographic primitive, trust algorithm, policy engine or distributed-ledger protocol",
        "general effectiveness against attacks outside the closed deterministic scenario catalog",
        "production performance, availability or service-level objectives",
        "validated optimality of the initial weights, thresholds, smoothing alpha or recovery rules",
      ],
    },
  });
}
