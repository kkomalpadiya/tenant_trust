import {
  EVALUATION_LABELS,
  EVALUATION_PROTOCOL_ID,
  EVALUATION_SAMPLE_PLAN,
  EVALUATION_SCENARIOS,
  classifyAccessObservation,
} from "./evaluation-protocol.mjs";

export const WORKLOAD_RUNNER_ID = "tenant-trust-workload-runner-v1";

const ADAPTER_STATUSES = new Set(["completed", "unsupported"]);
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{2,63}$/u;
const MEASUREMENT_PATTERN = /^[a-z][a-zA-Z0-9]*Ms$/u;

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function step(stepId, operation, fixture, expectedControls = []) {
  return { stepId, operation, fixture, expectedControls };
}

export const EVALUATION_SCENARIO_STEPS = deepFreeze({
  "eval-normal-legitimate-access": [
    step("normal-access", "authorize", "normal-access"),
  ],
  "eval-unknown-device-sensitive-export": [
    step("unknown-device-signal", "ingest-evidence", "unknown-device", ["detect-context-change"]),
    step("sensitive-export-after-unknown-device", "authorize", "sensitive-export", ["restrict-sensitive-export"]),
  ],
  "eval-failed-logins-sensitive-export": [
    step("failed-login-signal", "ingest-evidence", "failed-logins", ["detect-behaviour-change"]),
    step("sensitive-export-after-failed-logins", "authorize", "sensitive-export", ["restrict-sensitive-export"]),
  ],
  "eval-certificate-and-evidence-replay": [
    step("accepted-evidence", "ingest-evidence", "valid-evidence"),
    step("forged-evidence", "ingest-evidence", "forged-evidence", ["reject-forged-evidence"]),
    step("replayed-evidence", "ingest-evidence", "replayed-evidence", ["reject-replayed-evidence"]),
    step("reused-invalid-certificate", "authorize", "invalid-certificate-reuse", ["reject-invalid-certificate-reuse"]),
  ],
  "eval-cross-tenant-access": [
    step("cross-tenant-access", "authorize", "cross-tenant-access", ["deny-before-data-access", "preserve-other-tenant-state"]),
  ],
  "eval-evidence-flooding": [
    step("evidence-flood", "ingest-evidence", "evidence-flood", ["bound-source-influence", "preserve-other-tenant-capacity"]),
  ],
  "eval-policy-version-change": [
    step("publish-policy-version", "change-policy", "policy-version-change", ["bind-decision-to-active-policy"]),
    step("stale-policy-decision", "authorize", "stale-policy-version", ["fail-closed-on-version-mismatch"]),
  ],
  "eval-off-chain-audit-record-modification": [
    step("modify-off-chain-audit-record", "tamper-audit", "modified-audit-record"),
    step("verify-modified-audit-chain", "verify-audit", "modified-audit-record", ["detect-audit-modification", "identify-causal-break"]),
  ],
  "eval-fabric-outage-and-recovery": [
    step("start-ledger-outage", "set-ledger-state", "ledger-unavailable"),
    step("access-during-ledger-outage", "authorize", "normal-access", ["keep-ledger-off-critical-path"]),
    step("restore-ledger", "set-ledger-state", "ledger-available"),
    step("reconcile-pending-commitments", "reconcile-ledger", "pending-commitments", ["reconcile-pending-commitments"]),
  ],
  "eval-corroborated-revocation-enforcement": [
    step("corroborated-critical-evidence", "ingest-evidence", "corroborated-critical-evidence", ["revoke-after-corroborated-critical-evidence"]),
    step("reuse-revoked-certificate", "authorize", "revoked-certificate-reuse", ["deny-revoked-certificate"]),
  ],
});

function assertCatalogMatchesProtocol() {
  const protocolIds = EVALUATION_SCENARIOS.map(({ scenarioId }) => scenarioId);
  const catalogIds = Object.keys(EVALUATION_SCENARIO_STEPS);
  if (protocolIds.length !== catalogIds.length || protocolIds.some((id) => !catalogIds.includes(id))) {
    throw new Error("Workload step catalog does not match the pre-registered evaluation scenarios.");
  }
}

function assertConfigurationHash(configurationHash) {
  if (!HASH_PATTERN.test(configurationHash)) {
    throw new TypeError("configurationHash must be a lowercase SHA-256 digest.");
  }
}

function runId({ profile, concurrency, repetitionIndex, modeId, scenarioId }) {
  return [WORKLOAD_RUNNER_ID, profile, `c${concurrency}`, `r${repetitionIndex}`, modeId, scenarioId].join("/");
}

export function createEvaluationWorkloadPlan({
  configurationHash,
  profile = "full",
} = {}) {
  assertCatalogMatchesProtocol();
  assertConfigurationHash(configurationHash);
  if (!new Set(["full", "verification"]).has(profile)) {
    throw new TypeError("profile must be full or verification.");
  }

  const protocolPlan = EVALUATION_SAMPLE_PLAN.evaluation;
  const concurrencyLevels = profile === "full" ? protocolPlan.concurrencyLevels : [1];
  const warmups = profile === "full" ? protocolPlan.warmupRepetitionsPerScenarioModeLoad : 0;
  const measured = profile === "full" ? protocolPlan.measuredRepetitionsPerScenarioModeLoad : 1;
  const runs = [];

  for (const [loadIndex, concurrency] of concurrencyLevels.entries()) {
    for (let repetitionIndex = 0; repetitionIndex < warmups + measured; repetitionIndex += 1) {
      const modeOrder = protocolPlan.modeOrderRotation[repetitionIndex % protocolPlan.modeOrderRotation.length];
      const sampleKind = profile === "verification"
        ? "verification"
        : repetitionIndex < warmups ? "warmup" : "measured";
      const measuredRepetitionIndex = sampleKind === "measured" ? repetitionIndex - warmups : null;

      for (const [modeOrderIndex, modeId] of modeOrder.entries()) {
        for (const [scenarioIndex, scenario] of EVALUATION_SCENARIOS.entries()) {
          const seed = protocolPlan.seedBase + scenarioIndex * 10000 + loadIndex * 1000 + repetitionIndex;
          runs.push({
            runId: runId({ profile, concurrency, repetitionIndex, modeId, scenarioId: scenario.scenarioId }),
            protocolId: EVALUATION_PROTOCOL_ID,
            runnerId: WORKLOAD_RUNNER_ID,
            configurationHash,
            profile,
            sampleKind,
            measuredRepetitionIndex,
            repetitionIndex,
            loadIndex,
            concurrency,
            modeOrderIndex,
            modeId,
            scenarioId: scenario.scenarioId,
            seed,
          });
        }
      }
    }
  }

  const measuredRuns = runs.filter(({ sampleKind }) => sampleKind === "measured").length;
  if (profile === "full" && measuredRuns !== protocolPlan.totalMeasuredScenarioRuns) {
    throw new Error("Generated plan does not match the pre-registered measured scenario count.");
  }

  return deepFreeze({
    runnerId: WORKLOAD_RUNNER_ID,
    protocolId: EVALUATION_PROTOCOL_ID,
    configurationHash,
    profile,
    resultEligibility: profile === "full" ? "protocol-evaluation" : "runner-verification-only",
    runs,
  });
}

function adapterFor(adapters, modeId) {
  const adapter = adapters instanceof Map ? adapters.get(modeId) : adapters?.[modeId];
  if (!adapter || typeof adapter.executeStep !== "function") {
    throw new TypeError(`Missing executeStep adapter for mode ${modeId}.`);
  }
  return adapter;
}

function validateAdapterResult(result) {
  if (!result || typeof result !== "object" || !ADAPTER_STATUSES.has(result.status)) {
    throw new TypeError("Adapter result status must be completed or unsupported.");
  }
  if (!EVALUATION_LABELS.observedOutcomes.includes(result.observedOutcome)) {
    throw new TypeError("Adapter result has an unknown observed outcome.");
  }
  if (!REASON_PATTERN.test(result.reasonCode)) {
    throw new TypeError("Adapter result reasonCode must be a stable uppercase code.");
  }
  if (!Array.isArray(result.controlsObserved) || result.controlsObserved.some((control) => typeof control !== "string")) {
    throw new TypeError("Adapter result controlsObserved must be an array of strings.");
  }
  if (result.status === "unsupported" && result.observedOutcome !== "unsupported") {
    throw new TypeError("Unsupported adapter results must use the unsupported outcome.");
  }
  if (result.measurements !== undefined) {
    if (!result.measurements || typeof result.measurements !== "object" || Array.isArray(result.measurements)) {
      throw new TypeError("Adapter result measurements must be an object.");
    }
    for (const [measurementId, value] of Object.entries(result.measurements)) {
      if (!MEASUREMENT_PATTERN.test(measurementId) || !Number.isFinite(value) || value < 0) {
        throw new TypeError("Adapter measurements must be non-negative millisecond values.");
      }
    }
  }
  return result;
}

async function executeWithTimeout(adapter, context, timeoutMs) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timeout: true }), timeoutMs);
  });
  const execution = Promise.resolve().then(() => adapter.executeStep(context)).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  const response = await Promise.race([execution, timeout]);
  clearTimeout(timer);
  return response;
}

function failureResult(outcome, reasonCode) {
  return {
    status: outcome,
    observedOutcome: outcome,
    reasonCode,
    controlsObserved: [],
  };
}

async function executeLane({ run, scenario, steps, adapter, laneIndex, timeoutMs, nowNs }) {
  const observations = [];
  for (const [stepIndex, workloadStep] of steps.entries()) {
    const controller = new AbortController();
    const startedNs = nowNs();
    const response = await executeWithTimeout(adapter, {
      signal: controller.signal,
      run,
      scenario,
      step: workloadStep,
      stepIndex,
      laneIndex,
    }, timeoutMs);
    if (response?.timeout) controller.abort();
    const endedNs = nowNs();
    let result;
    if (response?.timeout) result = failureResult("timeout", "ADAPTER_TIMEOUT");
    else if (response?.error) result = failureResult("error", "ADAPTER_ERROR");
    else {
      try {
        result = validateAdapterResult(response.value);
      } catch {
        result = failureResult("error", "INVALID_ADAPTER_RESULT");
      }
    }

    const controlsObserved = [...new Set(result.controlsObserved)].sort();
    const controlsMissing = workloadStep.expectedControls.filter((control) => !controlsObserved.includes(control));
    observations.push({
      protocolId: run.protocolId,
      runnerId: run.runnerId,
      configurationHash: run.configurationHash,
      runId: run.runId,
      profile: run.profile,
      sampleKind: run.sampleKind,
      modeId: run.modeId,
      scenarioId: run.scenarioId,
      trafficClass: scenario.trafficClass,
      accessTruth: scenario.groundTruth.accessTruth,
      concurrency: run.concurrency,
      repetitionIndex: run.repetitionIndex,
      measuredRepetitionIndex: run.measuredRepetitionIndex,
      seed: run.seed,
      laneIndex,
      stepIndex,
      stepId: workloadStep.stepId,
      operation: workloadStep.operation,
      fixture: workloadStep.fixture,
      status: result.status,
      observedOutcome: result.observedOutcome,
      accessClassification: classifyAccessObservation({
        accessTruth: scenario.groundTruth.accessTruth,
        observedOutcome: result.observedOutcome,
      }),
      reasonCode: result.reasonCode,
      controlsExpected: workloadStep.expectedControls,
      controlsObserved,
      controlsMissing,
      measurements: result.measurements ?? {},
      startedNs: startedNs.toString(),
      durationNs: (endedNs - startedNs).toString(),
    });
  }
  return observations;
}

export async function runEvaluationWorkload({
  plan,
  adapters,
  timeoutMs = 5_000,
  nowNs = process.hrtime.bigint,
} = {}) {
  if (!plan || plan.runnerId !== WORKLOAD_RUNNER_ID || !Array.isArray(plan.runs)) {
    throw new TypeError("plan must be created by createEvaluationWorkloadPlan.");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError("timeoutMs must be a positive integer.");
  if (typeof nowNs !== "function") throw new TypeError("nowNs must be a function.");

  const scenarioById = new Map(EVALUATION_SCENARIOS.map((scenario) => [scenario.scenarioId, scenario]));
  const observations = [];
  const adaptersByMode = new Map([...new Set(plan.runs.map(({ modeId }) => modeId))].map((modeId) => (
    [modeId, adapterFor(adapters, modeId)]
  )));

  for (const run of plan.runs) {
    const scenario = scenarioById.get(run.scenarioId);
    const steps = EVALUATION_SCENARIO_STEPS[run.scenarioId];
    const adapter = adaptersByMode.get(run.modeId);
    const laneResults = await Promise.all(Array.from({ length: run.concurrency }, (_, laneIndex) => (
      executeLane({ run, scenario, steps, adapter, laneIndex, timeoutMs, nowNs })
    )));
    for (const lane of laneResults) observations.push(...lane);
  }

  return deepFreeze({
    runnerId: WORKLOAD_RUNNER_ID,
    protocolId: plan.protocolId,
    configurationHash: plan.configurationHash,
    profile: plan.profile,
    resultEligibility: plan.resultEligibility,
    plannedRuns: plan.runs.length,
    completedRuns: plan.runs.length,
    observationCount: observations.length,
    observations,
  });
}
