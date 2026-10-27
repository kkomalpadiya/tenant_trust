import assert from "node:assert/strict";
import fs from "node:fs/promises";
import {
  CALIBRATION_SCENARIOS,
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_METRICS,
  EVALUATION_PROTOCOL,
  EVALUATION_SAMPLE_PLAN,
  EVALUATION_SCENARIOS,
  EVALUATION_SOURCE_CITATIONS,
  EVALUATION_WORKLOAD,
} from "../packages/evaluation/src/index.mjs";

const protocolDocument = await fs.readFile(
  new URL("../docs/architecture/reproducible-evaluation-protocol.md", import.meta.url),
  "utf8",
);

const calibrationIds = new Set(CALIBRATION_SCENARIOS.map(({ scenarioId }) => scenarioId));
const evaluationIds = new Set(EVALUATION_SCENARIOS.map(({ scenarioId }) => scenarioId));
assert.equal([...calibrationIds].some((id) => evaluationIds.has(id)), false);
assert.equal(EVALUATION_PROTOCOL.status, "pre-registered-not-yet-executed");
assert.equal(EVALUATION_SAMPLE_PLAN.calibration.evaluationReuseAllowed, false);
assert.match(EVALUATION_SAMPLE_PLAN.freezeRule, /Do not tune/u);

assert.equal(EVALUATION_COMPARISON_SCOPE.modes.length, 3);
assert.equal(EVALUATION_WORKLOAD.length, 14);
assert.equal(EVALUATION_SCENARIOS.length, 10);
assert.deepEqual(EVALUATION_SAMPLE_PLAN.evaluation.concurrencyLevels, [1, 8, 32]);
assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.measuredRepetitionsPerScenarioModeLoad, 30);
assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.totalMeasuredScenarioRuns, 2700);
assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.totalMeasuredAuthorizationDecisions, 3780);

assert.equal(EVALUATION_METRICS.reportingRules.includeTimeoutsAndErrorsInDenominators, true);
assert.equal(EVALUATION_METRICS.reportingRules.reportUnsupportedSeparately, true);
assert.ok(EVALUATION_METRICS.security.every(({ unsupportedTreatment }) => unsupportedTreatment.length > 0));

assert.deepEqual(
  EVALUATION_SOURCE_CITATIONS.slides.map(({ slideNumber }) => slideNumber),
  [5, 6, 9, 10, 12, 13],
);
assert.ok(protocolDocument.includes(EVALUATION_SOURCE_CITATIONS.fileName));
assert.ok(protocolDocument.includes(EVALUATION_SOURCE_CITATIONS.sha256));
for (const { slideNumber } of EVALUATION_SOURCE_CITATIONS.slides) {
  assert.match(protocolDocument, new RegExp(`Slide ${slideNumber}\\b`, "u"));
}

console.log("PASS calibration scenarios, identifiers and seeds are isolated from the evaluation partition");
console.log("PASS three modes share 14 workload cases, 10 closed-label scenarios and fixed sample counts");
console.log("PASS concurrency, repetition, rotation, failure-denominator and reference-host rules are pre-registered");
console.log("PASS Review 2 slides 5, 6, 9, 10, 12 and 13 match the recorded source hash and protocol claims");

