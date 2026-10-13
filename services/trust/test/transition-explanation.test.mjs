import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  TRUST_EXPLANATION_POLICY,
  TrustTransitionExplanationError,
  buildTrustTransitionExplanation,
  canonicalizeTrustExplanation,
  createPostgresTrustTransitionRepository,
  createTrustTransitionExplanationService,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  previousTransition: "trn_018f1234-5678-7abc-8def-0123456789ac",
  event: "evt_018f1234-5678-7abc-8def-0123456789ab",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
};
const componentIds = ["identity", "device", "behaviour", "certificate", "compliance"];

function reference(componentId, index) {
  const suffix = String(index + 1).padStart(12, "0");
  return {
    evidenceId: `evd_018f1234-5678-7abc-8def-${suffix}`,
    sourceEventId: `evt_018f1234-5678-7abc-8def-${suffix}`,
    evidenceType: componentId,
  };
}

function input(overrides = {}) {
  const evidenceReferences = componentIds.map(reference);
  return {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    updateVersion: 1,
    correlationId: ids.correlation,
    causationId: evidenceReferences[4].sourceEventId,
    components: {
      identity: 80,
      device: 60,
      behaviour: 70,
      certificate: 100,
      compliance: 90,
    },
    evidenceReferences,
    configuration: {
      modelVersion: "1.0.0",
      configurationVersion: 1,
      initialScore: 60,
      smoothingAlpha: 0.5,
      staleAfterSeconds: 3600,
      weights: {
        identity: 0.2,
        device: 0.25,
        behaviour: 0.25,
        certificate: 0.15,
        compliance: 0.15,
      },
    },
    observedAt: "2026-10-12T08:00:00.000Z",
    source: {
      sourceId: "src_018f1234-5678-7abc-8def-0123456789ab",
      maximumInfluence: 0.25,
      corroboratingSourceIds: ["src_018f1234-5678-7abc-8def-0123456789ac"],
    },
    criticalEvidence: null,
    ...overrides,
  };
}

function build(overrides = {}) {
  return buildTrustTransitionExplanation({
    transitionId: ids.transition,
    eventId: ids.event,
    producer: { service: "trust-engine", instanceId: "test-1" },
    evaluatedAt: "2026-10-12T08:00:01.000Z",
    input: input(),
    previousTransition: null,
    ...overrides,
  });
}

test("assembles one deterministic cold-start explanation from the existing calculation stages", () => {
  const result = build();
  assert.equal(result.weightedScore, 77);
  assert.equal(result.smoothedScore, 68.5);
  assert.equal(result.previousState.band, "uninitialized");
  assert.equal(result.newState.band, "medium");
  assert.equal(result.transition, "held");
  assert.equal(result.contributions.length, 5);
  assert.deepEqual(result.contributions.map(({ componentId }) => componentId), componentIds);
  assert.deepEqual(result.explanation.evidenceReferences, input().evidenceReferences);
  assert.equal(result.explanation.policy, TRUST_EXPLANATION_POLICY);
});

test("hashes canonical explanation bytes and emits the existing trust event contract shape", () => {
  const result = build();
  assert.equal(
    result.explanationHashSha256,
    createHash("sha256").update(result.explanationJson, "utf8").digest("hex"),
  );
  assert.equal(result.event.eventType, "trust.updated.v1");
  assert.equal(result.event.aggregateId, ids.transition);
  assert.equal(result.event.payload.previousBand, "uninitialized");
  assert.equal(result.event.payload.newBand, "conditional");
  assert.equal(result.event.payload.explanationHashSha256, result.explanationHashSha256);
  assert.deepEqual(result.event.payload.evidenceIds, input().evidenceReferences.map((item) => item.evidenceId));
  assert.equal(result.eventSha256, createHash("sha256").update(result.eventJson).digest("hex"));
});

test("canonicalization is stable across object insertion order", () => {
  assert.equal(
    canonicalizeTrustExplanation({ z: 1, a: { y: 2, x: [3, true] } }),
    canonicalizeTrustExplanation({ a: { x: [3, true], y: 2 }, z: 1 }),
  );
});

test("records prior and new state for a deterioration without losing temporal history", () => {
  const prior = {
    transitionId: ids.previousTransition,
    updateVersion: 1,
    score: 80,
    band: "high",
    recoveryStreak: 0,
    temporalState: {
      score: 80,
      anchorScore: 80,
      lastFreshObservedAt: "2026-10-12T07:00:00.000Z",
      lastEvaluatedAt: "2026-10-12T07:00:01.000Z",
    },
  };
  const result = buildTrustTransitionExplanation({
    transitionId: ids.transition,
    eventId: ids.event,
    producer: { service: "trust-engine", instanceId: "test-1" },
    evaluatedAt: "2026-10-12T08:00:01.000Z",
    input: input({
      updateVersion: 2,
      components: Object.fromEntries(componentIds.map((componentId) => [componentId, 0])),
    }),
    previousTransition: prior,
  });
  assert.equal(result.previousTransitionId, ids.previousTransition);
  assert.deepEqual(result.explanation.previousState, prior);
  assert.equal(result.newState.score, 55);
  assert.equal(result.newState.band, "medium");
  assert.equal(result.transition, "deteriorated");
  assert.equal(result.event.payload.previousBand, "trusted");
  assert.equal(result.event.payload.newBand, "conditional");
});

test("records critical override details while allowing only the closed negative rules", () => {
  const result = build({
    input: input({
      criticalEvidence: { kind: "certificate-revoked", componentId: "certificate" },
    }),
  });
  assert.equal(result.newState.score, 0);
  assert.equal(result.newState.band, "low");
  assert.equal(result.transition, "critical-override");
  assert.deepEqual(result.explanation.transitionControl.criticalOverride, {
    kind: "certificate-revoked",
    componentId: "certificate",
    scoreCeiling: 0,
    forcedBand: "low",
  });
});

test("rejects malformed authority, causation, references and previous state", () => {
  const cases = [
    { input: input({ tenantId: "tenant-alpha" }) },
    { input: input({ causationId: ids.event }) },
    { input: input({ evidenceReferences: input().evidenceReferences.slice(1) }) },
    {
      input: input({ updateVersion: 2 }),
      previousTransition: {
        transitionId: ids.previousTransition,
        updateVersion: 2,
        score: 80,
        band: "high",
        recoveryStreak: 0,
        temporalState: {
          score: 80,
          anchorScore: 80,
          lastFreshObservedAt: "2026-10-12T07:00:00.000Z",
          lastEvaluatedAt: "2026-10-12T07:00:01.000Z",
        },
      },
    },
  ];
  for (const candidate of cases) {
    assert.throws(
      () => build(candidate),
      TrustTransitionExplanationError,
    );
  }
});

test("returns deeply immutable explanations and events", () => {
  const result = build();
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.explanation.weightedCalculation.contributions), true);
  assert.equal(Object.isFrozen(result.event.payload.evidenceIds), true);
  assert.throws(() => {
    result.explanation.newState.score = 1;
  }, TypeError);
});

test("the service generates server-owned identities and requires durable confirmation", async () => {
  const records = [];
  const uuids = [
    "018f1234-5678-7abc-8def-0123456789ab",
    "018f1234-5678-7abc-8def-0123456789ac",
  ];
  const service = createTrustTransitionExplanationService({
    producer: { service: "trust-engine", instanceId: "worker-1" },
    clock: () => new Date("2026-10-12T08:00:01.000Z"),
    idFactory: () => uuids.shift(),
    repository: {
      async record(record) {
        records.push(record);
        return {
          tenantId: record.tenantId,
          subjectId: record.subjectId,
          transitionId: record.transitionId,
          eventId: record.eventId,
          updateVersion: record.updateVersion,
          explanationHashSha256: record.explanationHashSha256,
          eventSha256: record.eventSha256,
          recordedAt: record.evaluatedAt,
        };
      },
    },
  });
  const result = await service.record(input());
  assert.equal(result.transitionId, ids.transition);
  assert.equal(result.eventId, "evt_018f1234-5678-7abc-8def-0123456789ac");
  assert.equal(records.length, 1);
  assert.equal(Object.isFrozen(result.persistence), true);
});

test("the PostgreSQL repository writes one parameterized least-privilege transaction", async () => {
  const record = build();
  const calls = [];
  const client = {
    async query(query) {
      calls.push(query);
      if (query.text.includes("record_subject_trust_transition")) {
        return {
          rows: [{
            tenant_id: record.tenantId,
            subject_id: record.subjectId,
            transition_id: record.transitionId,
            event_id: record.eventId,
            update_version: String(record.updateVersion),
            explanation_hash_sha256: record.explanationHashSha256,
            event_sha256: record.eventSha256,
            recorded_at: record.evaluatedAt,
          }],
        };
      }
      return { rows: [] };
    },
    release() {},
  };
  const repository = createPostgresTrustTransitionRepository({
    pool: { async connect() { return client; } },
  });
  const confirmation = await repository.record(record);
  assert.equal(confirmation.transitionId, ids.transition);
  assert.equal(calls[0].text, "BEGIN");
  assert.equal(calls[1].text, "SET LOCAL ROLE tenant_trust_trust_engine");
  assert.match(calls[2].text, /record_subject_trust_transition/u);
  assert.equal(calls[2].values.length, 26);
  assert.equal(calls[3].text, "COMMIT");
});

test("repository failures roll back and malformed confirmations fail closed", async () => {
  const record = build();
  let released = false;
  const calls = [];
  const repository = createPostgresTrustTransitionRepository({
    pool: {
      async connect() {
        return {
          async query(query) {
            calls.push(query.text);
            if (query.text.includes("record_subject_trust_transition")) return { rows: [] };
            return { rows: [] };
          },
          release() { released = true; },
        };
      },
    },
  });
  await assert.rejects(
    () => repository.record(record),
    (error) => error instanceof TrustTransitionExplanationError
      && error.reasonCode === "TRUST_TRANSITION_CONFIRMATION_INVALID",
  );
  assert.equal(calls.at(-1), "ROLLBACK");
  assert.equal(released, true);
});
