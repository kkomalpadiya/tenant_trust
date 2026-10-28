import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_PROTOCOL_ID,
  EVALUATION_SCENARIO_STEPS,
  EVALUATION_SCENARIOS,
  WORKLOAD_RUNNER_ID,
  createEvaluationWorkloadPlan,
  runEvaluationWorkload,
} from "../packages/evaluation/src/index.mjs";

const configurationHash = createHash("sha256")
  .update(`${EVALUATION_PROTOCOL_ID}/${WORKLOAD_RUNNER_ID}/verification`)
  .digest("hex");

const calls = [];
const adapters = Object.fromEntries(EVALUATION_COMPARISON_SCOPE.modes.map(({ modeId }) => [
  modeId,
  {
    async executeStep({ run, scenario, step, stepIndex, laneIndex }) {
      calls.push({ modeId, scenarioId: scenario.scenarioId, stepId: step.stepId, stepIndex, laneIndex, seed: run.seed });
      const observedOutcome = scenario.groundTruth.accessTruth === "legitimate-allow" ? "allow" : "deny";
      return {
        status: "completed",
        observedOutcome,
        reasonCode: "VERIFICATION_HARNESS_DECISION",
        controlsObserved: step.expectedControls,
      };
    },
  },
]));

const plan = createEvaluationWorkloadPlan({ configurationHash, profile: "verification" });
const result = await runEvaluationWorkload({ plan, adapters });
const expectedStepsPerMode = Object.values(EVALUATION_SCENARIO_STEPS).reduce((total, steps) => total + steps.length, 0);

assert.equal(plan.resultEligibility, "runner-verification-only");
assert.equal(plan.runs.length, EVALUATION_SCENARIOS.length * EVALUATION_COMPARISON_SCOPE.modes.length);
assert.equal(result.observationCount, expectedStepsPerMode * EVALUATION_COMPARISON_SCOPE.modes.length);
assert.equal(result.observationCount, calls.length);
assert.ok(result.observations.every(({ controlsMissing }) => controlsMissing.length === 0));
assert.deepEqual(
  new Set(result.observations.map(({ modeId }) => modeId)),
  new Set(EVALUATION_COMPARISON_SCOPE.modes.map(({ modeId }) => modeId)),
);

const fixtures = new Set(result.observations.map(({ fixture }) => fixture));
for (const required of [
  "normal-access",
  "unknown-device",
  "failed-logins",
  "sensitive-export",
  "cross-tenant-access",
  "forged-evidence",
  "replayed-evidence",
  "ledger-unavailable",
  "pending-commitments",
]) assert.ok(fixtures.has(required), `Missing required replay fixture: ${required}`);

const outageSteps = EVALUATION_SCENARIO_STEPS["eval-fabric-outage-and-recovery"].map(({ stepId }) => stepId);
assert.deepEqual(outageSteps, [
  "start-ledger-outage",
  "access-during-ledger-outage",
  "restore-ledger",
  "reconcile-pending-commitments",
]);

console.log("Benign and attack workload runner verification passed.");
console.log(`Runner: ${WORKLOAD_RUNNER_ID}`);
console.log(`Scenarios replayed: ${EVALUATION_SCENARIOS.length}`);
console.log(`Comparison modes replayed: ${EVALUATION_COMPARISON_SCOPE.modes.length}`);
console.log(`Raw observations retained: ${result.observationCount}`);
console.log("Result eligibility: runner verification only (no benchmark claim)");
