import assert from "node:assert/strict";
import { test } from "node:test";
import {
  summarizeLatency,
  summarizeRate,
  summarizeRecovery,
  summarizeResourceUse,
  validatePerformanceCoverage,
} from "../src/performance-metrics.mjs";

test("latency, rate and recovery summaries use deterministic interpolated percentiles", () => {
  assert.deepEqual(summarizeLatency([4, 1, 2, 3]), {
    count: 4, p50: 2.5, p95: 3.85, p99: 3.97, max: 4,
  });
  assert.deepEqual(summarizeRate([10, 30, 20]), { count: 3, median: 20, min: 10, max: 30 });
  assert.deepEqual(summarizeRecovery([2500, 1500, 2000]), { count: 3, median: 2000, max: 2500 });
});

test("resource summaries retain counts and normalize CPU and memory units", () => {
  assert.deepEqual(summarizeResourceUse({
    cpuMicroseconds: 12_500,
    decisionCount: 5,
    rssStartBytes: 10 * 1_048_576,
    rssEndBytes: 11 * 1_048_576,
    rssPeakBytes: 12 * 1_048_576,
  }), {
    decisionCount: 5,
    cpuMilliseconds: 12.5,
    cpuMillisecondsPerDecision: 2.5,
    rssStartMiB: 10,
    rssEndMiB: 11,
    rssPeakMiB: 12,
  });
});

test("coverage validation rejects missing, duplicate and incomplete mode/load blocks", () => {
  const plan = { modeIds: ["a", "b"], concurrencyLevels: [1, 8], measuredDecisionsPerBlock: 42 };
  const complete = ["a", "b"].flatMap((modeId) => [1, 8].map((concurrency) => ({
    modeId, concurrency, measuredDecisionCount: 42,
  })));
  assert.equal(validatePerformanceCoverage(complete, plan), true);
  assert.throws(() => validatePerformanceCoverage(complete.slice(1), plan), /missing/u);
  assert.throws(() => validatePerformanceCoverage([...complete, complete[0]], plan), /duplicate/u);
  assert.throws(() => validatePerformanceCoverage([{ ...complete[0], measuredDecisionCount: 41 }, ...complete.slice(1)], plan), /Incomplete/u);
});

test("summaries reject empty, negative and inconsistent observations", () => {
  assert.throws(() => summarizeLatency([]), TypeError);
  assert.throws(() => summarizeRate([-1]), TypeError);
  assert.throws(() => summarizeResourceUse({
    cpuMicroseconds: 1,
    decisionCount: 1,
    rssStartBytes: 2,
    rssEndBytes: 2,
    rssPeakBytes: 1,
  }), TypeError);
});
