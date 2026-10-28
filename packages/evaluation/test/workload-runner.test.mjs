import assert from "node:assert/strict";
import { test } from "node:test";

import {
  EVALUATION_SAMPLE_PLAN,
  EVALUATION_SCENARIO_STEPS,
  EVALUATION_SCENARIOS,
  WORKLOAD_RUNNER_ID,
  createEvaluationWorkloadPlan,
  runEvaluationWorkload,
} from "../src/index.mjs";

const configurationHash = "a".repeat(64);

function completedAdapter(overrides = {}) {
  return {
    async executeStep({ step }) {
      return {
        status: "completed",
        observedOutcome: "deny",
        reasonCode: "TEST_DECISION",
        controlsObserved: step.expectedControls,
        measurements: step.fixture === "revoked-certificate-reuse" ? { revocationEnforcementDelayMs: 275 } : undefined,
        ...overrides,
      };
    },
  };
}

function adaptersFor(plan, factory = completedAdapter) {
  return Object.fromEntries([...new Set(plan.runs.map(({ modeId }) => modeId))].map((modeId) => [modeId, factory()]));
}

test("catalog covers every scenario and the required benign and adversarial fixtures", () => {
  assert.deepEqual(Object.keys(EVALUATION_SCENARIO_STEPS), EVALUATION_SCENARIOS.map(({ scenarioId }) => scenarioId));
  for (const scenario of EVALUATION_SCENARIOS) {
    const coveredControls = EVALUATION_SCENARIO_STEPS[scenario.scenarioId].flatMap(({ expectedControls }) => expectedControls);
    assert.ok(scenario.groundTruth.requiredControls.every((control) => coveredControls.includes(control)));
  }
  const fixtures = Object.values(EVALUATION_SCENARIO_STEPS).flat().map(({ fixture }) => fixture);
  for (const required of [
    "normal-access",
    "unknown-device",
    "failed-logins",
    "sensitive-export",
    "cross-tenant-access",
    "forged-evidence",
    "replayed-evidence",
    "ledger-unavailable",
  ]) assert.ok(fixtures.includes(required), required);
});

test("full plan exactly implements the registered loads, repetitions and measured count", () => {
  const plan = createEvaluationWorkloadPlan({ configurationHash });
  assert.equal(plan.runnerId, WORKLOAD_RUNNER_ID);
  assert.equal(plan.profile, "full");
  assert.equal(plan.resultEligibility, "protocol-evaluation");
  assert.equal(plan.runs.filter(({ sampleKind }) => sampleKind === "warmup").length, 450);
  assert.equal(plan.runs.filter(({ sampleKind }) => sampleKind === "measured").length, 2700);
  assert.deepEqual([...new Set(plan.runs.map(({ concurrency }) => concurrency))], [1, 8, 32]);
  assert.equal(plan.runs.length, 3150);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.totalMeasuredScenarioRuns, 2700);
});

test("plan creation is deterministic and rotates mode order without changing scenario seeds", () => {
  const first = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  const second = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  assert.deepEqual(first, second);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(new Set(first.runs.slice(0, 30).map(({ seed }) => seed)).size, EVALUATION_SCENARIOS.length);
  assert.equal(first.runs[0].modeOrderIndex, 0);
  assert.equal(first.runs[10].modeOrderIndex, 1);
  assert.equal(first.runs[20].modeOrderIndex, 2);
});

test("verification plan replays every scenario through all three comparison modes", async () => {
  const plan = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  const result = await runEvaluationWorkload({ plan, adapters: adaptersFor(plan) });
  assert.equal(plan.runs.length, EVALUATION_SCENARIOS.length * 3);
  assert.equal(result.completedRuns, plan.runs.length);
  assert.equal(result.resultEligibility, "runner-verification-only");
  assert.deepEqual(new Set(result.observations.map(({ scenarioId }) => scenarioId)), new Set(EVALUATION_SCENARIOS.map(({ scenarioId }) => scenarioId)));
  assert.ok(result.observations.every(({ controlsMissing }) => controlsMissing.length === 0));
  assert.ok(result.observations.some(({ measurements }) => measurements.revocationEnforcementDelayMs === 275));
});

test("runner executes each lane concurrently while preserving step order within a lane", async () => {
  const base = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  const selected = { ...base, runs: [{ ...base.runs[3], concurrency: 4 }] };
  const calls = [];
  const adapter = {
    async executeStep({ laneIndex, stepIndex, step }) {
      calls.push(`${laneIndex}:${stepIndex}`);
      return completedAdapter().executeStep({ step });
    },
  };
  const result = await runEvaluationWorkload({ plan: selected, adapters: { [selected.runs[0].modeId]: adapter } });
  assert.equal(result.observationCount, EVALUATION_SCENARIO_STEPS[selected.runs[0].scenarioId].length * 4);
  for (let laneIndex = 0; laneIndex < 4; laneIndex += 1) {
    assert.deepEqual(result.observations.filter((item) => item.laneIndex === laneIndex).map(({ stepIndex }) => stepIndex), [0, 1, 2, 3]);
  }
  assert.deepEqual(new Set(calls.slice(0, 4)), new Set(["0:0", "1:0", "2:0", "3:0"]));
});

test("unsupported behavior, adapter errors and invalid results remain explicit observations", async () => {
  const base = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  const selected = { ...base, runs: [base.runs[0], base.runs[1]] };
  let call = 0;
  const adapter = {
    async executeStep() {
      call += 1;
      if (call === 1) return { status: "unsupported", observedOutcome: "unsupported", reasonCode: "CONTROL_UNSUPPORTED", controlsObserved: [] };
      if (call === 2) throw new Error("synthetic failure");
      return { status: "completed", observedOutcome: "not-a-label", reasonCode: "BAD", controlsObserved: [] };
    },
  };
  const result = await runEvaluationWorkload({ plan: selected, adapters: { [selected.runs[0].modeId]: adapter } });
  assert.deepEqual(result.observations.map(({ observedOutcome }) => observedOutcome), ["unsupported", "error", "error"]);
  assert.deepEqual(result.observations.map(({ reasonCode }) => reasonCode), ["CONTROL_UNSUPPORTED", "ADAPTER_ERROR", "INVALID_ADAPTER_RESULT"]);
});

test("timeouts remain explicit observations instead of being dropped", async () => {
  const base = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  const selected = { ...base, runs: [base.runs[0]] };
  const adapter = { executeStep: async () => new Promise(() => {}) };
  const result = await runEvaluationWorkload({ plan: selected, adapters: { [selected.runs[0].modeId]: adapter }, timeoutMs: 5 });
  assert.equal(result.observationCount, 1);
  assert.equal(result.observations[0].observedOutcome, "timeout");
  assert.equal(result.observations[0].reasonCode, "ADAPTER_TIMEOUT");
});

test("runner rejects unregistered setup instead of silently skipping a mode", async () => {
  assert.throws(() => createEvaluationWorkloadPlan({ configurationHash: "not-a-hash" }), TypeError);
  const plan = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
  await assert.rejects(() => runEvaluationWorkload({ plan, adapters: {} }), /Missing executeStep adapter/u);
});
