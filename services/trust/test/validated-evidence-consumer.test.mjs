import assert from "node:assert/strict";
import { test } from "node:test";
import {
  VALIDATED_EVIDENCE_CONSUMPTION_POLICY,
  ValidatedEvidenceConsumptionError,
  createPostgresValidatedEvidenceRepository,
  createValidatedEvidenceTrustConsumer,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  event: "evt_018f1234-5678-7abc-8def-0123456789ab",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789ab",
};

function event(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    eventId: ids.event,
    eventType: "evidence.accepted.v1",
    tenantId: ids.tenant,
    subjectId: ids.subject,
    aggregateId: ids.evidence,
    payload: { evidenceType: "identity" },
    ...overrides,
  };
}

function databaseRow(overrides = {}) {
  return {
    applied: true,
    outcome_code: "state_updated",
    tenant_id: ids.tenant,
    subject_id: ids.subject,
    evidence_type: "identity",
    update_version: "1",
    ...overrides,
  };
}

function poolWith(handler) {
  const calls = [];
  let released = false;
  const client = {
    async query(configuration) {
      calls.push(configuration);
      return handler(configuration, calls.length);
    },
    release() {
      released = true;
    },
  };
  return {
    calls,
    get released() {
      return released;
    },
    async connect() {
      return client;
    },
  };
}

test("publishes the immutable ordering and idempotency policy", () => {
  assert.deepEqual(VALIDATED_EVIDENCE_CONSUMPTION_POLICY, {
    deliverySemantics: "at-least-once-delivery-exactly-once-effect",
    aggregateScope: "tenant-and-subject",
    concurrencyControl: "transaction-advisory-lock-per-tenant-subject",
    ordering: "observed-at-then-stream-sequence-then-event-id",
    incompleteEvidence: "stage-until-all-five-components-exist",
    olderEvidence: "record-effect-without-state-rollback",
  });
  assert.ok(Object.isFrozen(VALIDATED_EVIDENCE_CONSUMPTION_POLICY));
});

test("verifies delivery before resolving and atomically persisting its component", async () => {
  const calls = [];
  const inputEvent = event();
  const consumer = createValidatedEvidenceTrustConsumer({
    consumerName: "trust-engine.v1",
    async verifyEvent({ event: delivered, expectedTenantId }) {
      calls.push("verify");
      assert.equal(delivered, inputEvent);
      assert.equal(expectedTenantId, ids.tenant);
      return delivered;
    },
    async resolveComponentScore({ event: delivered, verified }) {
      calls.push("resolve");
      assert.equal(delivered, inputEvent);
      assert.equal(verified, inputEvent);
      return 91.25;
    },
    repository: {
      async consume(delivery) {
        calls.push("persist");
        assert.equal(delivery.consumerName, "trust-engine.v1");
        assert.equal(delivery.event, inputEvent);
        assert.equal(delivery.componentScore, 91.25);
        assert.equal(delivery.streamSequence, 42);
        assert.match(delivery.signedEventSha256, /^[0-9a-f]{64}$/u);
        return {
          applied: true,
          outcome: "state_updated",
          tenantId: ids.tenant,
          subjectId: ids.subject,
          evidenceType: "identity",
          updateVersion: 1,
        };
      },
    },
  });

  const result = await consumer.consume({
    event: inputEvent,
    streamSequence: 42,
    expectedTenantId: ids.tenant,
    resolvePublicKey: () => "unused-by-test-verifier",
  });

  assert.deepEqual(calls, ["verify", "resolve", "persist"]);
  assert.equal(result.applied, true);
  assert.equal(result.outcome, "state_updated");
  assert.equal(result.updateVersion, 1);
  assert.ok(Object.isFrozen(result));
});

test("reports durable redelivery suppression without a second state effect", async () => {
  const consumer = createValidatedEvidenceTrustConsumer({
    consumerName: "trust-engine.v1",
    verifyEvent: async ({ event: delivered }) => delivered,
    resolveComponentScore: async () => 70,
    repository: {
      async consume() {
        return {
          applied: false,
          outcome: "duplicate",
          tenantId: ids.tenant,
          subjectId: ids.subject,
          evidenceType: "identity",
          updateVersion: 3,
        };
      },
    },
  });
  const result = await consumer.consume({
    event: event(),
    streamSequence: 42,
    expectedTenantId: ids.tenant,
    resolvePublicKey: () => null,
  });
  assert.equal(result.applied, false);
  assert.equal(result.outcome, "duplicate");
  assert.equal(result.updateVersion, 3);
});

test("verification failure prevents score resolution and persistence", async () => {
  const failure = new Error("signature rejected");
  let resolved = false;
  let persisted = false;
  const consumer = createValidatedEvidenceTrustConsumer({
    consumerName: "trust-engine.v1",
    verifyEvent: async () => { throw failure; },
    resolveComponentScore: async () => { resolved = true; return 50; },
    repository: { consume: async () => { persisted = true; } },
  });
  await assert.rejects(consumer.consume({
    event: event(),
    streamSequence: 42,
    expectedTenantId: ids.tenant,
    resolvePublicKey: () => null,
  }), failure);
  assert.equal(resolved, false);
  assert.equal(persisted, false);
});

test("invalid normalized component scores fail before database access", async () => {
  let persisted = false;
  const consumer = createValidatedEvidenceTrustConsumer({
    consumerName: "trust-engine.v1",
    verifyEvent: async ({ event: delivered }) => delivered,
    resolveComponentScore: async () => 101,
    repository: { consume: async () => { persisted = true; } },
  });
  await assert.rejects(
    consumer.consume({
      event: event(),
      streamSequence: 42,
      expectedTenantId: ids.tenant,
      resolvePublicKey: () => null,
    }),
    (error) => error instanceof ValidatedEvidenceConsumptionError
      && error.reasonCode === "COMPONENT_SCORE_INVALID",
  );
  assert.equal(persisted, false);
});

test("concurrent consumer calls keep their verification and persistence results isolated", async () => {
  const secondEvent = event({
    eventId: "evt_018f1234-5678-7abc-8def-0123456789ac",
    aggregateId: "evd_018f1234-5678-7abc-8def-0123456789ac",
    payload: { evidenceType: "device" },
  });
  const consumer = createValidatedEvidenceTrustConsumer({
    consumerName: "trust-engine.v1",
    verifyEvent: async ({ event: delivered }) => delivered,
    resolveComponentScore: async ({ event: delivered }) => (
      delivered.payload.evidenceType === "identity" ? 91 : 82
    ),
    repository: {
      async consume(delivery) {
        if (delivery.event.payload.evidenceType === "identity") {
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        return {
          applied: true,
          outcome: "staged",
          tenantId: ids.tenant,
          subjectId: ids.subject,
          evidenceType: delivery.event.payload.evidenceType,
          updateVersion: null,
        };
      },
    },
  });

  const [identityResult, deviceResult] = await Promise.all([
    consumer.consume({
      event: event(),
      streamSequence: 42,
      expectedTenantId: ids.tenant,
      resolvePublicKey: () => null,
    }),
    consumer.consume({
      event: secondEvent,
      streamSequence: 43,
      expectedTenantId: ids.tenant,
      resolvePublicKey: () => null,
    }),
  ]);

  assert.equal(identityResult.eventId, ids.event);
  assert.equal(identityResult.evidenceType, "identity");
  assert.equal(deviceResult.eventId, secondEvent.eventId);
  assert.equal(deviceResult.evidenceType, "device");
});

test("PostgreSQL repository calls one parameterized least-privilege transaction", async () => {
  const pool = poolWith(async ({ text }) => {
    if (text.includes("consume_validated_evidence_component")) {
      return { rows: [databaseRow()] };
    }
    return { rows: [] };
  });
  const repository = createPostgresValidatedEvidenceRepository({
    pool,
    clock: () => new Date("2026-10-06T08:00:03.000Z"),
  });
  const inputEvent = event();
  const result = await repository.consume({
    consumerName: "trust-engine.v1",
    event: inputEvent,
    verified: inputEvent,
    streamSequence: 42,
    signedEventSha256: "a".repeat(64),
    componentScore: 91.25,
  });

  assert.deepEqual(result, {
    applied: true,
    outcome: "state_updated",
    tenantId: ids.tenant,
    subjectId: ids.subject,
    evidenceType: "identity",
    updateVersion: 1,
  });
  assert.deepEqual(pool.calls.map(({ text }) => text.trim()), [
    "BEGIN",
    "SET LOCAL ROLE tenant_trust_evidence_event_consumer",
    pool.calls[2].text.trim(),
    "COMMIT",
  ]);
  assert.match(pool.calls[2].text, /consume_validated_evidence_component/u);
  assert.deepEqual(pool.calls[2].values, [
    "trust-engine.v1",
    ids.tenant,
    ids.event,
    ids.evidence,
    42,
    "a".repeat(64),
    91.25,
    "2026-10-06T08:00:03.000Z",
  ]);
  assert.equal(pool.released, true);
});

test("PostgreSQL failures roll back and malformed confirmations fail closed", async () => {
  const failure = new Error("write failed");
  const failingPool = poolWith(async ({ text }) => {
    if (text.includes("consume_validated_evidence_component")) throw failure;
    return { rows: [] };
  });
  const input = {
    consumerName: "trust-engine.v1",
    event: event(),
    verified: event(),
    streamSequence: 42,
    signedEventSha256: "a".repeat(64),
    componentScore: 91.25,
  };
  const failingRepository = createPostgresValidatedEvidenceRepository({
    pool: failingPool,
    clock: () => new Date("2026-10-06T08:00:03.000Z"),
  });
  await assert.rejects(failingRepository.consume(input), failure);
  assert.equal(failingPool.calls.at(-1).text, "ROLLBACK");
  assert.equal(failingPool.released, true);

  const malformedPool = poolWith(async ({ text }) => (
    text.includes("consume_validated_evidence_component")
      ? { rows: [databaseRow({ subject_id: "sub_other" })] }
      : { rows: [] }
  ));
  const malformedRepository = createPostgresValidatedEvidenceRepository({
    pool: malformedPool,
    clock: () => new Date("2026-10-06T08:00:03.000Z"),
  });
  await assert.rejects(
    malformedRepository.consume(input),
    (error) => error instanceof ValidatedEvidenceConsumptionError
      && error.reasonCode === "CONSUMPTION_RESULT_INVALID",
  );
  assert.equal(malformedPool.calls.at(-1).text, "ROLLBACK");
});
