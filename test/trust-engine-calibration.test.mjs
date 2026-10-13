import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { createInMemoryEvidenceReplayGuard } from "@tenant-trust/evidence";
import {
  advanceSmoothedTrustScore,
  applyTrustTransitionControls,
  calculateWeightedTrustScore,
  initializeTrustControlState,
} from "@tenant-trust/trust";

const fixturePath = resolve(import.meta.dirname, "fixtures/trust-engine-calibration-v1.json");
const fixtures = JSON.parse(readFileSync(fixturePath, "utf8"));
const clock = () => new Date("2026-10-13T08:05:00.000Z");

const ids = Object.freeze({
  alphaTenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  betaTenant: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alphaSubject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  betaSubject: "sub_018f1234-5678-7abc-8def-0123456789ac",
  source: "src_018f1234-5678-7abc-8def-0123456789e0",
  key: "key_018f1234-5678-7abc-8def-0123456789e0",
});

function candidate(overrides = {}) {
  return {
    tenantId: ids.alphaTenant,
    subjectId: ids.alphaSubject,
    sourceId: ids.source,
    keyId: ids.key,
    eventId: "evt_018f1234-5678-7abc-8def-0123456789e0",
    evidenceType: "identity",
    sourceSequence: 1,
    nonce: "AAAAAAAAAAAAAAAAAAAAAA",
    contentHashSha256: "ab".repeat(32),
    synthetic: true,
    maximumAgeSeconds: 300,
    observedAt: "2026-10-13T08:04:55.000Z",
    expiresAt: "2026-10-13T08:09:55.000Z",
    ...overrides,
  };
}

test("labels the fixture catalog as unvalidated deterministic regression data", () => {
  assert.equal(fixtures.schemaVersion, "tenant-trust-calibration-fixtures-v1");
  assert.equal(fixtures.calibrationStatus, "UNVALIDATED_PROTOTYPE_DEFAULTS");
  assert.equal(fixtures.purpose, "deterministic-regression-only");
  assert.equal(fixtures.effectivenessClaim, false);
});

test("checks normalized score boundaries and one independent default-weight calculation", () => {
  for (const fixture of fixtures.weightedCases) {
    assert.equal(calculateWeightedTrustScore(fixture.components).score, fixture.expectedScore, fixture.id);
  }
});

test("checks the exact freshness boundary plus missing and stale signal behavior", () => {
  for (const fixture of fixtures.temporalCases) {
    const result = advanceSmoothedTrustScore(fixture);
    assert.deepEqual({
      score: result.score,
      phase: result.phase,
      observationStatus: result.observationStatus,
    }, fixture.expected, fixture.id);
  }
});

test("checks band boundaries and corroborated two-step recovery", () => {
  for (const fixture of fixtures.bandBoundaries) {
    assert.equal(initializeTrustControlState(fixture.score).band, fixture.expectedBand);
  }

  let state = fixtures.recoveryCase.initialState;
  fixtures.recoveryCase.candidateScores.forEach((candidateScore, index) => {
    const result = applyTrustTransitionControls({
      previousState: state,
      candidateScore,
      source: fixtures.recoveryCase.source,
    });
    assert.deepEqual({
      score: result.score,
      band: result.band,
      transition: result.transition,
      recoveryStreak: result.recoveryStreak,
    }, fixtures.recoveryCase.expected[index]);
    state = result.state;
  });
});

test("rejects replayed event, nonce and sequence identities", async () => {
  const guard = createInMemoryEvidenceReplayGuard({ clock });
  const base = candidate();
  const attempts = [
    base,
    base,
    candidate({
      eventId: "evt_018f1234-5678-7abc-8def-0123456789e1",
      sourceSequence: 2,
    }),
    candidate({
      eventId: "evt_018f1234-5678-7abc-8def-0123456789e2",
      nonce: "BBBBBBBBBBBBBBBBBBBBBB",
    }),
  ];
  const outcomes = [];
  for (const attempt of attempts) outcomes.push((await guard(attempt)).reasonCode);
  assert.deepEqual(outcomes, fixtures.replayCase.expectedOutcomes);
});

test("rate-limits a flood, suspends only its source and preserves the effective influence cap", async () => {
  const guard = createInMemoryEvidenceReplayGuard({
    clock,
    safeguards: fixtures.floodCase.safeguards,
  });
  const outcomes = [];
  for (let index = 0; index < fixtures.floodCase.expectedOutcomes.length; index += 1) {
    const hexadecimal = index.toString(16);
    outcomes.push((await guard(candidate({
      eventId: `evt_018f1234-5678-7abc-8def-0123456789e${hexadecimal}`,
      sourceSequence: index + 1,
      nonce: `${"A".repeat(21)}${String.fromCharCode(65 + index)}`,
    }))).reasonCode);
  }
  assert.deepEqual(outcomes, fixtures.floodCase.expectedOutcomes);
  const [control] = guard.snapshot().sourceControls;
  assert.equal(control.acceptedCount, fixtures.floodCase.expectedAcceptedCount);
  assert.equal(control.rateLimitedCount, fixtures.floodCase.expectedRateLimitedCount);
  assert.equal(control.suspended, true);
  assert.equal(
    control.maximumSourceInfluence,
    fixtures.floodCase.expectedEffectiveMaximumInfluence,
  );
});

test("keeps replay and flood state tenant scoped even for identical identifiers", async () => {
  const guard = createInMemoryEvidenceReplayGuard({ clock });
  const [alphaTenant, betaTenant] = fixtures.tenantIsolationCase.tenantIds;
  const results = await Promise.all([
    guard(candidate({ tenantId: alphaTenant, subjectId: ids.alphaSubject })),
    guard(candidate({ tenantId: betaTenant, subjectId: ids.betaSubject })),
  ]);
  assert.equal(results.filter((result) => result.accepted).length,
    fixtures.tenantIsolationCase.expectedIndependentAccepts);
  assert.deepEqual(
    guard.snapshot().sourceControls.map((control) => control.sourceScope).sort(),
    [`${alphaTenant}:${ids.source}`, `${betaTenant}:${ids.source}`].sort(),
  );
});
