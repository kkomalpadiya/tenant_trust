export const PERFORMANCE_REPORT_ID = "tenant-trust-performance-recovery-report-v1";

function finiteSamples(samples, label) {
  if (!Array.isArray(samples) || samples.length === 0
    || samples.some((value) => typeof value !== "number" || !Number.isFinite(value) || value < 0)) {
    throw new TypeError(`${label} requires one or more finite non-negative samples.`);
  }
  return [...samples].sort((left, right) => left - right);
}

function round(value, decimalPlaces = 3) {
  const factor = 10 ** decimalPlaces;
  return Math.round((value + Number.EPSILON) * factor) / factor;
}

function percentile(sorted, probability) {
  if (sorted.length === 1) return sorted[0];
  const rank = probability * (sorted.length - 1);
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  const weight = rank - lower;
  return sorted[lower] + (sorted[upper] - sorted[lower]) * weight;
}

export function summarizeLatency(samples) {
  const sorted = finiteSamples(samples, "Latency summary");
  return Object.freeze({
    count: sorted.length,
    p50: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
    max: round(sorted.at(-1)),
  });
}

export function summarizeRate(samples) {
  const sorted = finiteSamples(samples, "Rate summary");
  return Object.freeze({
    count: sorted.length,
    median: round(percentile(sorted, 0.5)),
    min: round(sorted[0]),
    max: round(sorted.at(-1)),
  });
}

export function summarizeRecovery(samples) {
  const sorted = finiteSamples(samples, "Recovery summary");
  return Object.freeze({
    count: sorted.length,
    median: round(percentile(sorted, 0.5)),
    max: round(sorted.at(-1)),
  });
}

export function summarizeResourceUse({ cpuMicroseconds, decisionCount, rssStartBytes, rssEndBytes, rssPeakBytes }) {
  if (!Number.isFinite(cpuMicroseconds) || cpuMicroseconds < 0
    || !Number.isSafeInteger(decisionCount) || decisionCount < 1
    || [rssStartBytes, rssEndBytes, rssPeakBytes].some((value) => !Number.isSafeInteger(value) || value < 0)
    || rssPeakBytes < Math.max(rssStartBytes, rssEndBytes)) {
    throw new TypeError("Resource summary requires valid CPU, decision and RSS observations.");
  }
  return Object.freeze({
    decisionCount,
    cpuMilliseconds: round(cpuMicroseconds / 1_000),
    cpuMillisecondsPerDecision: round(cpuMicroseconds / 1_000 / decisionCount, 6),
    rssStartMiB: round(rssStartBytes / 1_048_576),
    rssEndMiB: round(rssEndBytes / 1_048_576),
    rssPeakMiB: round(rssPeakBytes / 1_048_576),
  });
}

export function validatePerformanceCoverage(blocks, { modeIds, concurrencyLevels, measuredDecisionsPerBlock }) {
  if (!Array.isArray(blocks) || !Array.isArray(modeIds) || !Array.isArray(concurrencyLevels)
    || !Number.isSafeInteger(measuredDecisionsPerBlock) || measuredDecisionsPerBlock < 1) {
    throw new TypeError("A complete performance coverage plan is required.");
  }
  const expected = new Set(modeIds.flatMap((modeId) => concurrencyLevels.map((load) => `${modeId}\u0000${load}`)));
  for (const block of blocks) {
    const key = `${block?.modeId}\u0000${block?.concurrency}`;
    if (!expected.delete(key)) throw new Error(`Unexpected or duplicate performance block: ${key.replace("\u0000", "/")}.`);
    if (block.measuredDecisionCount !== measuredDecisionsPerBlock) {
      throw new Error(`Incomplete measured decision coverage for ${block.modeId}/${block.concurrency}.`);
    }
  }
  if (expected.size > 0) throw new Error("Performance report is missing registered mode/load blocks.");
  return true;
}
