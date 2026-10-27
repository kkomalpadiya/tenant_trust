import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CALIBRATION_SCENARIOS,
  COMPARISON_WORKLOAD_ID,
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_LABELS,
  EVALUATION_METRICS,
  EVALUATION_PROTOCOL,
  EVALUATION_PROTOCOL_ID,
  EVALUATION_REFERENCE_HOST,
  EVALUATION_SAMPLE_PLAN,
  EVALUATION_SCENARIOS,
  EVALUATION_SOURCE_CITATIONS,
  EVALUATION_WORKLOAD,
  classifyAccessObservation,
} from "../src/index.mjs";

test("protocol binds every mode to the existing immutable comparison workload", () => {
  assert.equal(EVALUATION_PROTOCOL.protocolId, EVALUATION_PROTOCOL_ID);
  assert.equal(EVALUATION_PROTOCOL.workloadId, COMPARISON_WORKLOAD_ID);
  assert.deepEqual(
    EVALUATION_SAMPLE_PLAN.modeIds,
    EVALUATION_COMPARISON_SCOPE.modes.map(({ modeId }) => modeId),
  );
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.workloadCasesPerReplay, EVALUATION_WORKLOAD.length);
  assert.equal(Object.isFrozen(EVALUATION_PROTOCOL), true);
});

test("calibration and evaluation use disjoint scenario identifiers and seed namespaces", () => {
  const calibrationIds = new Set(CALIBRATION_SCENARIOS.map(({ scenarioId }) => scenarioId));
  const evaluationIds = new Set(EVALUATION_SCENARIOS.map(({ scenarioId }) => scenarioId));
  assert.equal([...calibrationIds].some((id) => evaluationIds.has(id)), false);
  assert.ok(CALIBRATION_SCENARIOS.every(({ partition, seedNamespace }) => (
    partition === "calibration" && seedNamespace.startsWith("tenant-trust-calibration-v1/")
  )));
  assert.ok(EVALUATION_SCENARIOS.every(({ partition, seedNamespace }) => (
    partition === "evaluation" && seedNamespace.startsWith("tenant-trust-evaluation-v1/")
  )));
  assert.equal(EVALUATION_SAMPLE_PLAN.calibration.evaluationReuseAllowed, false);
  assert.match(EVALUATION_SAMPLE_PLAN.freezeRule, /Do not tune/u);
});

test("sample counts, loads, repetitions and rotation are fixed before execution", () => {
  assert.deepEqual(EVALUATION_SAMPLE_PLAN.evaluation.concurrencyLevels, [1, 8, 32]);
  assert.equal(EVALUATION_SAMPLE_PLAN.calibration.instancesPerScenario, 20);
  assert.equal(EVALUATION_SAMPLE_PLAN.calibration.seedBase, 20261027);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.warmupRepetitionsPerScenarioModeLoad, 5);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.measuredRepetitionsPerScenarioModeLoad, 30);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.totalMeasuredScenarioRuns, 2700);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.totalMeasuredAuthorizationDecisions, 3780);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.seedBase, 20261028);
  assert.equal(EVALUATION_SAMPLE_PLAN.evaluation.modeOrderRotation.length, 3);
  assert.ok(EVALUATION_SAMPLE_PLAN.evaluation.modeOrderRotation.every((order) => (
    new Set(order).size === EVALUATION_SAMPLE_PLAN.modeIds.length
  )));
});

test("every evaluation scenario has closed ground truth and declared metric eligibility", () => {
  assert.equal(EVALUATION_SCENARIOS.length, 10);
  assert.deepEqual(new Set(EVALUATION_SCENARIOS.map(({ trafficClass }) => trafficClass)), new Set(EVALUATION_LABELS.trafficClasses));
  for (const entry of EVALUATION_SCENARIOS) {
    assert.ok(EVALUATION_LABELS.accessTruth.includes(entry.groundTruth.accessTruth));
    assert.ok(entry.groundTruth.expectedAuthorizationOutcomes.every((outcome) => EVALUATION_LABELS.observedOutcomes.includes(outcome)));
    assert.ok(entry.metricEligibility.length > 0);
    if (entry.trafficClass === "attack") assert.ok(entry.groundTruth.requiredControls.length > 0);
  }
});

test("access labels distinguish false restriction from missed restriction", () => {
  assert.equal(classifyAccessObservation({ accessTruth: "legitimate-allow", observedOutcome: "allow" }), "correct-allow");
  assert.equal(classifyAccessObservation({ accessTruth: "legitimate-allow", observedOutcome: "step-up" }), "false-restriction");
  assert.equal(classifyAccessObservation({ accessTruth: "unauthorized-restrict", observedOutcome: "deny" }), "correct-restriction");
  assert.equal(classifyAccessObservation({ accessTruth: "unauthorized-restrict", observedOutcome: "allow" }), "missed-restriction");
  assert.equal(classifyAccessObservation({ accessTruth: "control-only", observedOutcome: "unsupported" }), "control-only");
  assert.throws(() => classifyAccessObservation({ accessTruth: "unknown", observedOutcome: "allow" }), TypeError);
});

test("metric denominators retain failures and unsupported controls", () => {
  const securityMetrics = EVALUATION_METRICS.security;
  assert.ok(securityMetrics.every(({ numerator, denominator, unsupportedTreatment }) => (
    numerator.length > 0 && denominator.length > 0 && unsupportedTreatment.length > 0
  )));
  assert.equal(EVALUATION_METRICS.reportingRules.includeTimeoutsAndErrorsInDenominators, true);
  assert.equal(EVALUATION_METRICS.reportingRules.reportUnsupportedSeparately, true);
  assert.equal(EVALUATION_METRICS.reportingRules.omitFailedSamplesFromLatencyDistributions, false);
  assert.equal(EVALUATION_METRICS.reportingRules.bootstrapResamples, 10000);
  assert.equal(EVALUATION_METRICS.reportingRules.bootstrapSeed, 20261029);
});

test("reference hardware is exact but excludes private machine identifiers", () => {
  assert.equal(EVALUATION_REFERENCE_HOST.cpu.physicalCores, 8);
  assert.equal(EVALUATION_REFERENCE_HOST.cpu.logicalProcessors, 16);
  assert.equal(EVALUATION_REFERENCE_HOST.runtime.node, "24.20.0");
  assert.equal(EVALUATION_REFERENCE_HOST.executionRules.concurrentUserWorkloadsAllowed, false);
  assert.equal("hostName" in EVALUATION_REFERENCE_HOST, false);
  assert.equal("serialNumber" in EVALUATION_REFERENCE_HOST, false);
});

test("presentation citations identify the verified revision and required slides", () => {
  assert.match(EVALUATION_SOURCE_CITATIONS.sha256, /^[a-f0-9]{64}$/u);
  assert.equal(EVALUATION_SOURCE_CITATIONS.verifiedOn, "2026-10-28");
  assert.deepEqual(
    EVALUATION_SOURCE_CITATIONS.slides.map(({ slideNumber }) => slideNumber),
    [5, 6, 9, 10, 12, 13],
  );
  assert.ok(EVALUATION_SOURCE_CITATIONS.slides.some(({ supports }) => supports.includes("separate-calibration-and-evaluation")));
  assert.ok(EVALUATION_SOURCE_CITATIONS.slides.some(({ supports }) => supports.includes("performance-metrics")));
});
