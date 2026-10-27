import {
  COMPARISON_WORKLOAD_ID,
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_WORKLOAD,
} from "./comparison-scope.mjs";

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export const EVALUATION_PROTOCOL_ID = "tenant-trust-evaluation-protocol-v1";

export const EVALUATION_LABELS = deepFreeze({
  partitions: ["calibration", "evaluation"],
  trafficClasses: ["benign", "attack", "resilience"],
  accessTruth: ["legitimate-allow", "unauthorized-restrict", "control-only"],
  observedOutcomes: ["allow", "step-up", "deny", "quarantine", "unsupported", "timeout", "error"],
  accessClassifications: [
    "correct-allow",
    "false-restriction",
    "correct-restriction",
    "missed-restriction",
    "control-only",
  ],
});

export const EVALUATION_SOURCE_CITATIONS = deepFreeze({
  sourceId: "review-2-adaptive-trust-framework",
  title: "Review 2: Adaptive Trust-Aware Security Framework for Multi-Tenant SaaS Platforms",
  fileName: "Review2_Adaptive_Trust_Framework.pptx",
  sha256: "68be85f2c8ca624f01cf978bc2b34aee2f6a7ba45a6ed01e51a628532ffb526d",
  verifiedOn: "2026-10-28",
  slides: [
    { slideNumber: 5, supports: ["synthetic-scenario-driven-dataset", "two-tenant-demonstration-scope"] },
    { slideNumber: 6, supports: ["scenario-catalog", "sample-count-deferred-to-protocol-task"] },
    { slideNumber: 9, supports: ["weights-require-calibration", "initial-values-are-not-validated"] },
    { slideNumber: 10, supports: ["trust-bands-are-evaluation-hypotheses", "access-outcome-labels"] },
    { slideNumber: 12, supports: ["separate-calibration-and-evaluation", "same-workload", "repetitions", "increasing-load"] },
    { slideNumber: 13, supports: ["performance-metrics", "security-metrics", "evaluation-hypotheses"] },
  ],
});

export const EVALUATION_REFERENCE_HOST = deepFreeze({
  hostProfileId: "tenant-trust-reference-host-v1",
  capturedOn: "2026-10-28",
  cpu: {
    model: "AMD Ryzen 7 7840HS with Radeon 780M Graphics",
    physicalCores: 8,
    logicalProcessors: 16,
  },
  memoryGiB: 15.3,
  storage: {
    model: "SAMSUNG MZVL41T0HBLB-00BH1",
    mediaType: "SSD",
    capacityGiB: 954,
  },
  operatingSystem: {
    name: "Microsoft Windows 11 Home Single Language",
    version: "10.0.26200",
    build: "26200",
  },
  runtime: {
    node: "24.20.0",
    npm: "10.8.3",
    dockerClient: "28.1.1",
    containerBackend: "Docker Desktop with WSL2",
  },
  executionRules: {
    singlePhysicalHost: true,
    acPowerRequired: true,
    localNetworkOnly: true,
    concurrentUserWorkloadsAllowed: false,
    modeBlocksRunSerially: true,
  },
});

const calibrationScenario = (scenarioId, trafficClass, tuningTargets) => ({
  scenarioId,
  partition: "calibration",
  seedNamespace: `tenant-trust-calibration-v1/${scenarioId}`,
  trafficClass,
  tuningTargets,
});

export const CALIBRATION_SCENARIOS = deepFreeze([
  calibrationScenario("cal-normal-member-read", "benign", ["normal-score-range", "allow-boundary"]),
  calibrationScenario("cal-unknown-device-read", "attack", ["device-penalty", "step-up-boundary"]),
  calibrationScenario("cal-failed-login-export", "attack", ["behaviour-penalty", "sensitive-deny-boundary"]),
  calibrationScenario("cal-threshold-jitter", "resilience", ["smoothing-alpha", "hysteresis-width"]),
  calibrationScenario("cal-critical-corroboration", "attack", ["source-cap", "critical-revocation-boundary"]),
]);

const scenario = ({
  scenarioId,
  trafficClass,
  accessTruth,
  expectedAuthorizationOutcomes,
  requiredControls,
  metricEligibility,
}) => ({
  scenarioId,
  partition: "evaluation",
  seedNamespace: `tenant-trust-evaluation-v1/${scenarioId}`,
  trafficClass,
  groundTruth: {
    accessTruth,
    expectedAuthorizationOutcomes,
    requiredControls,
  },
  metricEligibility,
});

export const EVALUATION_SCENARIOS = deepFreeze([
  scenario({
    scenarioId: "eval-normal-legitimate-access",
    trafficClass: "benign",
    accessTruth: "legitimate-allow",
    expectedAuthorizationOutcomes: ["allow"],
    requiredControls: [],
    metricEligibility: ["latency", "throughput", "false-restriction-rate"],
  }),
  scenario({
    scenarioId: "eval-unknown-device-sensitive-export",
    trafficClass: "attack",
    accessTruth: "unauthorized-restrict",
    expectedAuthorizationOutcomes: ["step-up", "deny", "quarantine"],
    requiredControls: ["detect-context-change", "restrict-sensitive-export"],
    metricEligibility: ["latency", "attack-detection-rate"],
  }),
  scenario({
    scenarioId: "eval-failed-logins-sensitive-export",
    trafficClass: "attack",
    accessTruth: "unauthorized-restrict",
    expectedAuthorizationOutcomes: ["step-up", "deny", "quarantine"],
    requiredControls: ["detect-behaviour-change", "restrict-sensitive-export"],
    metricEligibility: ["latency", "attack-detection-rate"],
  }),
  scenario({
    scenarioId: "eval-certificate-and-evidence-replay",
    trafficClass: "attack",
    accessTruth: "unauthorized-restrict",
    expectedAuthorizationOutcomes: ["deny", "quarantine"],
    requiredControls: ["reject-replayed-evidence", "reject-invalid-certificate-reuse"],
    metricEligibility: ["attack-detection-rate", "replay-rejection-rate"],
  }),
  scenario({
    scenarioId: "eval-cross-tenant-access",
    trafficClass: "attack",
    accessTruth: "unauthorized-restrict",
    expectedAuthorizationOutcomes: ["deny"],
    requiredControls: ["deny-before-data-access", "preserve-other-tenant-state"],
    metricEligibility: ["latency", "tenant-isolation-rate"],
  }),
  scenario({
    scenarioId: "eval-evidence-flooding",
    trafficClass: "attack",
    accessTruth: "control-only",
    expectedAuthorizationOutcomes: [],
    requiredControls: ["bound-source-influence", "preserve-other-tenant-capacity"],
    metricEligibility: ["attack-detection-rate", "tenant-isolation-rate"],
  }),
  scenario({
    scenarioId: "eval-policy-version-change",
    trafficClass: "resilience",
    accessTruth: "control-only",
    expectedAuthorizationOutcomes: [],
    requiredControls: ["bind-decision-to-active-policy", "fail-closed-on-version-mismatch"],
    metricEligibility: ["attack-detection-rate", "policy-provenance-rate"],
  }),
  scenario({
    scenarioId: "eval-off-chain-audit-record-modification",
    trafficClass: "attack",
    accessTruth: "control-only",
    expectedAuthorizationOutcomes: [],
    requiredControls: ["detect-audit-modification", "identify-causal-break"],
    metricEligibility: ["audit-modification-detection-rate", "ledger-verification-rate"],
  }),
  scenario({
    scenarioId: "eval-fabric-outage-and-recovery",
    trafficClass: "resilience",
    accessTruth: "control-only",
    expectedAuthorizationOutcomes: [],
    requiredControls: ["keep-ledger-off-critical-path", "reconcile-pending-commitments"],
    metricEligibility: ["ledger-commit-delay", "outage-recovery-time", "ledger-verification-rate"],
  }),
  scenario({
    scenarioId: "eval-corroborated-revocation-enforcement",
    trafficClass: "attack",
    accessTruth: "unauthorized-restrict",
    expectedAuthorizationOutcomes: ["deny", "quarantine"],
    requiredControls: ["revoke-after-corroborated-critical-evidence", "deny-revoked-certificate"],
    metricEligibility: ["attack-detection-rate", "revocation-enforcement-delay"],
  }),
]);

const modeIds = EVALUATION_COMPARISON_SCOPE.modes.map(({ modeId }) => modeId);

export const EVALUATION_SAMPLE_PLAN = deepFreeze({
  workloadId: COMPARISON_WORKLOAD_ID,
  modeIds,
  calibration: {
    scenarioCount: CALIBRATION_SCENARIOS.length,
    instancesPerScenario: 20,
    maximumCandidateConfigurations: 12,
    evaluationReuseAllowed: false,
    seedBase: 20261027,
    seedDerivation: "seedBase + scenarioIndex * 100 + instanceIndex",
  },
  evaluation: {
    scenarioCount: EVALUATION_SCENARIOS.length,
    concurrencyLevels: [1, 8, 32],
    warmupRepetitionsPerScenarioModeLoad: 5,
    measuredRepetitionsPerScenarioModeLoad: 30,
    workloadCasesPerReplay: EVALUATION_WORKLOAD.length,
    totalMeasuredScenarioRuns: EVALUATION_SCENARIOS.length * 30 * modeIds.length * 3,
    totalMeasuredAuthorizationDecisions: EVALUATION_WORKLOAD.length * 30 * modeIds.length * 3,
    settleSecondsBetweenModeBlocks: 10,
    seedBase: 20261028,
    seedDerivation: "seedBase + scenarioIndex * 10000 + loadIndex * 1000 + repetitionIndex",
    modeOrderRotation: [
      [modeIds[0], modeIds[1], modeIds[2]],
      [modeIds[1], modeIds[2], modeIds[0]],
      [modeIds[2], modeIds[0], modeIds[1]],
    ],
  },
  freezeRule: "Seal the configuration hash after calibration. Do not tune weights, bands, hysteresis, policies or labels after evaluation begins.",
});

export const EVALUATION_METRICS = deepFreeze({
  performance: [
    { metricId: "authentication-latency-ms", summary: ["p50", "p95", "p99", "max"] },
    { metricId: "trust-computation-latency-ms", summary: ["p50", "p95", "p99", "max"] },
    { metricId: "authorization-latency-ms", summary: ["p50", "p95", "p99", "max"] },
    { metricId: "end-to-end-decision-latency-ms", summary: ["p50", "p95", "p99", "max"] },
    { metricId: "request-throughput-per-second", summary: ["median", "min", "max"] },
    { metricId: "ledger-commit-delay-ms", summary: ["p50", "p95", "p99", "max"] },
    { metricId: "fabric-outage-recovery-time-ms", summary: ["median", "max"] },
  ],
  security: [
    {
      metricId: "attack-detection-rate",
      numerator: "attack trials where every required detection or restriction control is observed",
      denominator: "all attack trials with required controls",
      unsupportedTreatment: "count-as-miss",
    },
    {
      metricId: "false-restriction-rate",
      numerator: "benign legitimate trials with an observed outcome other than allow",
      denominator: "all benign legitimate access trials",
      unsupportedTreatment: "count-as-false-restriction",
    },
    {
      metricId: "tenant-isolation-rate",
      numerator: "isolation trials denied before foreign data access with the other tenant unchanged",
      denominator: "all cross-tenant and isolation stress trials",
      unsupportedTreatment: "count-as-failure",
    },
    {
      metricId: "replay-rejection-rate",
      numerator: "replay trials rejected without a state change",
      denominator: "all certificate and evidence replay trials",
      unsupportedTreatment: "count-as-failure",
    },
    {
      metricId: "audit-modification-detection-rate",
      numerator: "tamper trials whose causal verification fails at the modified record",
      denominator: "all audit modification trials",
      unsupportedTreatment: "count-as-failure",
    },
    {
      metricId: "ledger-verification-rate",
      numerator: "expected commitments verified after normal delivery or recovery",
      denominator: "all expected commitments",
      unsupportedTreatment: "count-as-failure",
    },
    {
      metricId: "revocation-enforcement-delay-ms",
      numerator: "elapsed time from confirmed revocation to the first denied reuse",
      denominator: "every corroborated revocation trial",
      unsupportedTreatment: "report-as-unbounded-failure",
    },
  ],
  reportingRules: {
    includeTimeoutsAndErrorsInDenominators: true,
    reportUnsupportedSeparately: true,
    omitFailedSamplesFromLatencyDistributions: false,
    confidenceInterval: "two-sided-bootstrap-95-percent",
    bootstrapResamples: 10000,
    bootstrapSeed: 20261029,
    rawResultRetention: "one row per measured observation with protocol, mode, scenario, load, repetition and seed labels",
  },
});

export const EVALUATION_PROTOCOL = deepFreeze({
  protocolId: EVALUATION_PROTOCOL_ID,
  status: "pre-registered-not-yet-executed",
  workloadId: COMPARISON_WORKLOAD_ID,
  labels: EVALUATION_LABELS,
  sources: EVALUATION_SOURCE_CITATIONS,
  referenceHost: EVALUATION_REFERENCE_HOST,
  calibrationScenarios: CALIBRATION_SCENARIOS,
  evaluationScenarios: EVALUATION_SCENARIOS,
  samplePlan: EVALUATION_SAMPLE_PLAN,
  metrics: EVALUATION_METRICS,
});

export function classifyAccessObservation({ accessTruth, observedOutcome }) {
  if (!EVALUATION_LABELS.accessTruth.includes(accessTruth)) throw new TypeError("Unknown access-truth label.");
  if (!EVALUATION_LABELS.observedOutcomes.includes(observedOutcome)) throw new TypeError("Unknown observed-outcome label.");
  if (accessTruth === "control-only") return "control-only";

  const allowed = observedOutcome === "allow";
  if (accessTruth === "legitimate-allow") return allowed ? "correct-allow" : "false-restriction";
  return allowed ? "missed-restriction" : "correct-restriction";
}

