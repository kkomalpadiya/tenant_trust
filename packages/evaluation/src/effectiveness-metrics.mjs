import {
  EVALUATION_METRICS,
  EVALUATION_PROTOCOL_ID,
  EVALUATION_SAMPLE_PLAN,
  EVALUATION_SCENARIOS,
} from "./evaluation-protocol.mjs";
import { WORKLOAD_RUNNER_ID } from "./workload-runner.mjs";

export const EFFECTIVENESS_REPORT_ID = "tenant-trust-effectiveness-isolation-report-v1";

const scenarios = new Map(EVALUATION_SCENARIOS.map((scenario) => [scenario.scenarioId, scenario]));
const ISOLATION_SCENARIOS = new Set(["eval-cross-tenant-access", "eval-evidence-flooding"]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function hashText(value) {
  let hash = 2166136261;
  for (const character of value) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function randomGenerator(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function percentile(sorted, probability) {
  if (sorted.length === 0) return null;
  const index = (sorted.length - 1) * probability;
  const lower = Math.floor(index);
  const fraction = index - lower;
  return sorted[lower] + (sorted[Math.min(lower + 1, sorted.length - 1)] - sorted[lower]) * fraction;
}

function round(value, digits = 6) {
  if (value === null) return null;
  return Number(value.toFixed(digits));
}

function bootstrapRate(clusters, seed, resamples) {
  if (clusters.length === 0) return { lower: null, upper: null };
  const random = randomGenerator(seed);
  const estimates = new Array(resamples);
  for (let sample = 0; sample < resamples; sample += 1) {
    let numerator = 0;
    let denominator = 0;
    for (let draw = 0; draw < clusters.length; draw += 1) {
      const cluster = clusters[Math.floor(random() * clusters.length)];
      numerator += cluster.numerator;
      denominator += cluster.denominator;
    }
    estimates[sample] = denominator === 0 ? 0 : numerator / denominator;
  }
  estimates.sort((a, b) => a - b);
  return { lower: percentile(estimates, 0.025), upper: percentile(estimates, 0.975) };
}

function median(values) {
  return percentile([...values].sort((a, b) => a - b), 0.5);
}

function bootstrapMedian(clusters, seed, resamples) {
  if (clusters.length === 0) return { lower: null, upper: null };
  const random = randomGenerator(seed);
  const estimates = new Array(resamples);
  for (let sample = 0; sample < resamples; sample += 1) {
    const values = [];
    for (let draw = 0; draw < clusters.length; draw += 1) {
      values.push(...clusters[Math.floor(random() * clusters.length)].values);
    }
    estimates[sample] = median(values);
  }
  estimates.sort((a, b) => a - b);
  return { lower: percentile(estimates, 0.025), upper: percentile(estimates, 0.975) };
}

function trialKey(observation) {
  return `${observation.modeId}\u0000${observation.runId}\u0000${observation.laneIndex}`;
}

function groupTrials(observations) {
  const trials = new Map();
  for (const observation of observations) {
    const key = trialKey(observation);
    if (!trials.has(key)) trials.set(key, []);
    trials.get(key).push(observation);
  }
  return [...trials.values()].map((items) => {
    items.sort((left, right) => left.stepIndex - right.stepIndex);
    const first = items[0];
    const scenario = scenarios.get(first.scenarioId);
    const controls = new Set(items.flatMap(({ controlsObserved }) => controlsObserved));
    const requiredControls = scenario.groundTruth.requiredControls;
    const controlsSatisfied = requiredControls.every((control) => controls.has(control));
    const outcomeSatisfied = scenario.groundTruth.accessTruth !== "unauthorized-restrict" || items.some((item) => (
      item.operation === "authorize" && scenario.groundTruth.expectedAuthorizationOutcomes.includes(item.observedOutcome)
    ));
    return {
      modeId: first.modeId,
      runId: first.runId,
      scenarioId: first.scenarioId,
      trafficClass: first.trafficClass,
      accessTruth: first.accessTruth,
      observations: items,
      controlsSatisfied,
      outcomeSatisfied,
      successful: controlsSatisfied && outcomeSatisfied,
    };
  });
}

function assertCompleteProtocolCoverage(trials) {
  const expectedPerScenarioMode = EVALUATION_SAMPLE_PLAN.evaluation.measuredRepetitionsPerScenarioModeLoad
    * EVALUATION_SAMPLE_PLAN.evaluation.concurrencyLevels.reduce((total, concurrency) => total + concurrency, 0);
  const expectedModes = new Set(EVALUATION_SAMPLE_PLAN.modeIds);
  const actualModes = new Set(trials.map(({ modeId }) => modeId));
  if (actualModes.size !== expectedModes.size || [...expectedModes].some((modeId) => !actualModes.has(modeId))) {
    throw new Error("Effectiveness report requires every registered comparison mode.");
  }
  for (const modeId of expectedModes) {
    for (const { scenarioId } of EVALUATION_SCENARIOS) {
      const count = trials.filter((trial) => trial.modeId === modeId && trial.scenarioId === scenarioId).length;
      if (count !== expectedPerScenarioMode) {
        throw new Error(`Incomplete measured trial coverage for ${modeId}/${scenarioId}.`);
      }
    }
  }
}

function rateMetric({ metricId, trials, success, seed, resamples, failureLabel }) {
  const clustersByRun = new Map();
  let numerator = 0;
  for (const trial of trials) {
    const passed = success(trial);
    if (passed) numerator += 1;
    if (!clustersByRun.has(trial.runId)) clustersByRun.set(trial.runId, { numerator: 0, denominator: 0 });
    const cluster = clustersByRun.get(trial.runId);
    cluster.numerator += passed ? 1 : 0;
    cluster.denominator += 1;
  }
  const denominator = trials.length;
  const interval = bootstrapRate([...clustersByRun.values()], seed, resamples);
  return {
    metricId,
    numerator,
    denominator,
    estimate: denominator === 0 ? null : round(numerator / denominator),
    ...(failureLabel ? { [failureLabel]: denominator - numerator } : {}),
    confidenceInterval: {
      method: "cluster-bootstrap-percentile",
      level: 0.95,
      resamples,
      seed,
      lower: round(interval.lower),
      upper: round(interval.upper),
    },
  };
}

function delayMetric({ trials, seed, resamples }) {
  const clustersByRun = new Map();
  const values = [];
  for (const trial of trials) {
    const delay = trial.observations.find(({ measurements }) => (
      Number.isFinite(measurements.revocationEnforcementDelayMs)
    ))?.measurements.revocationEnforcementDelayMs;
    if (trial.successful && Number.isFinite(delay)) {
      values.push(delay);
      if (!clustersByRun.has(trial.runId)) clustersByRun.set(trial.runId, { values: [] });
      clustersByRun.get(trial.runId).values.push(delay);
    }
  }
  const interval = bootstrapMedian([...clustersByRun.values()], seed, resamples);
  const ordered = [...values].sort((a, b) => a - b);
  return {
    metricId: "revocation-enforcement-delay-ms",
    successfulObservations: values.length,
    denominator: trials.length,
    unboundedFailures: trials.length - values.length,
    medianMs: round(percentile(ordered, 0.5), 3),
    p95Ms: round(percentile(ordered, 0.95), 3),
    confidenceInterval: {
      statistic: "median-ms",
      method: "cluster-bootstrap-percentile",
      level: 0.95,
      resamples,
      seed,
      lower: round(interval.lower, 3),
      upper: round(interval.upper, 3),
    },
  };
}

export function measureEffectivenessAndIsolation(workloadResult) {
  if (!workloadResult
    || workloadResult.runnerId !== WORKLOAD_RUNNER_ID
    || workloadResult.protocolId !== EVALUATION_PROTOCOL_ID
    || workloadResult.resultEligibility !== "protocol-evaluation") {
    throw new TypeError("A full protocol-evaluation workload result is required.");
  }
  const measured = workloadResult.observations.filter(({ sampleKind }) => sampleKind === "measured");
  const trials = groupTrials(measured);
  assertCompleteProtocolCoverage(trials);
  const modeIds = [...new Set(trials.map(({ modeId }) => modeId))].sort();
  const resamples = EVALUATION_METRICS.reportingRules.bootstrapResamples;
  const seedBase = EVALUATION_METRICS.reportingRules.bootstrapSeed;

  const modes = modeIds.map((modeId) => {
    const modeTrials = trials.filter((trial) => trial.modeId === modeId);
    const metricSeed = (metricId) => (seedBase + hashText(`${modeId}/${metricId}`)) >>> 0;
    const attacks = modeTrials.filter(({ trafficClass }) => trafficClass === "attack");
    const benign = modeTrials.filter(({ accessTruth }) => accessTruth === "legitimate-allow");
    const isolation = modeTrials.filter(({ scenarioId }) => ISOLATION_SCENARIOS.has(scenarioId));
    const replay = modeTrials.filter(({ scenarioId }) => scenarioId === "eval-certificate-and-evidence-replay");
    const audit = modeTrials.filter(({ scenarioId }) => scenarioId === "eval-off-chain-audit-record-modification");
    const ledger = modeTrials.filter(({ scenarioId }) => scenarioId === "eval-fabric-outage-and-recovery");
    const revocation = modeTrials.filter(({ scenarioId }) => scenarioId === "eval-corroborated-revocation-enforcement");

    return {
      modeId,
      measuredTrials: modeTrials.length,
      metrics: {
        attackDetectionRate: rateMetric({ metricId: "attack-detection-rate", trials: attacks, success: (trial) => trial.successful, seed: metricSeed("attack-detection-rate"), resamples }),
        falseRestrictionRate: rateMetric({
          metricId: "false-restriction-rate",
          trials: benign,
          success: (trial) => trial.observations.some(({ operation, observedOutcome }) => operation === "authorize" && observedOutcome !== "allow"),
          seed: metricSeed("false-restriction-rate"),
          resamples,
        }),
        tenantIsolationRate: rateMetric({ metricId: "tenant-isolation-rate", trials: isolation, success: (trial) => trial.successful, seed: metricSeed("tenant-isolation-rate"), resamples, failureLabel: "isolationFailures" }),
        replayRejectionRate: rateMetric({ metricId: "replay-rejection-rate", trials: replay, success: (trial) => trial.successful, seed: metricSeed("replay-rejection-rate"), resamples }),
        auditModificationDetectionRate: rateMetric({ metricId: "audit-modification-detection-rate", trials: audit, success: (trial) => trial.successful, seed: metricSeed("audit-modification-detection-rate"), resamples }),
        ledgerVerificationRate: rateMetric({ metricId: "ledger-verification-rate", trials: ledger, success: (trial) => trial.successful, seed: metricSeed("ledger-verification-rate"), resamples }),
        revocationEnforcementDelay: delayMetric({ trials: revocation, seed: metricSeed("revocation-enforcement-delay-ms"), resamples }),
      },
    };
  });

  return deepFreeze({
    reportId: EFFECTIVENESS_REPORT_ID,
    protocolId: workloadResult.protocolId,
    runnerId: workloadResult.runnerId,
    configurationHash: workloadResult.configurationHash,
    evaluationType: "deterministic-reference-functional-evaluation",
    rawObservationCount: workloadResult.observationCount,
    measuredObservationCount: measured.length,
    uncertainty: {
      method: "cluster-bootstrap-percentile",
      cluster: "scenario-mode-load-repetition run",
      level: 0.95,
      resamples,
      seedBase,
    },
    modes,
    limitations: [
      "Reference adapters exercise the frozen functional capability model; they are not production traffic or real-world prevalence estimates.",
      "Latency, throughput, resource use, ledger commit delay and outage recovery performance are excluded and belong to T10.8.",
    ],
  });
}
