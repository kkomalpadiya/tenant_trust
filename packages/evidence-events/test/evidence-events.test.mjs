import assert from "node:assert/strict";
import { generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  EvidenceEventError,
  buildUnsignedEvidenceAcceptedEvent,
  canonicalizeJson,
  createEvidenceAcceptedConsumer,
  createEvidenceAcceptedPublisher,
  createPostgresEvidenceEventEffectRepository,
  createPostgresEvidenceEventOutboxRepository,
  signEvidenceAcceptedEvent,
  verifyEvidenceAcceptedEvent,
} from "../src/index.mjs";

const schemaRoot = resolve(import.meta.dirname, "../../contracts/schemas");
const common = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const evidenceSchema = JSON.parse(readFileSync(resolve(schemaRoot, "events/evidence-event.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateEvent = ajv.compile(evidenceSchema);

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  source: "src_018f1234-5678-7abc-8def-0123456789ab",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789ab",
  event: "evt_018f1234-5678-7abc-8def-0123456789ab",
  sourceEvent: "evt_018f1234-5678-7abc-8def-0123456789ac",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
  claim: "clm_018f1234-5678-7abc-8def-0123456789ab",
};
const producer = { service: "evidence-events", instanceId: "test-1" };
const keyId = "evidence-events:key-2026-01";
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = (content) => ed25519Sign(null, content, privateKey);

function record(overrides = {}) {
  return {
    tenantId: ids.tenant,
    eventId: ids.event,
    sourceEventId: ids.sourceEvent,
    evidenceId: ids.evidence,
    correlationId: ids.correlation,
    subjectId: ids.subject,
    sourceId: ids.source,
    evidenceType: "identity",
    sourceSequence: 41,
    contentHashSha256: "ab".repeat(32),
    synthetic: true,
    observedAt: "2026-10-06T08:00:00.000Z",
    expiresAt: "2026-10-06T08:05:00.000Z",
    acceptedAt: "2026-10-06T08:00:01.000Z",
    claimToken: ids.claim,
    attemptCount: 1,
    ...overrides,
  };
}

function contextFor(tenantId = ids.tenant) {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "evidence-event-test", tenantId, subjectId: ids.subject },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: { tenantId, subjectId: ids.subject, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

test("accepted evidence builds a contract-valid metadata-only event", async () => {
  const event = await signEvidenceAcceptedEvent({ record: record(), producer, keyId, sign: signer, validateEvent });
  assert.equal(validateEvent(event), true, ajv.errorsText(validateEvent.errors));
  assert.equal(event.eventType, "evidence.accepted.v1");
  assert.equal(event.aggregateId, ids.evidence);
  assert.equal(event.causationId, ids.sourceEvent);
  assert.deepEqual(Object.keys(event.payload).sort(), [
    "contentHashSha256", "evidenceId", "evidenceType", "expiresAt",
    "observedAt", "sourceId", "sourceSequence", "synthetic",
  ]);
  assert.equal(canonicalizeJson(event).includes("ciphertext"), false);
});

test("signature verification binds tenant, producer key and immutable content", async () => {
  const event = await signEvidenceAcceptedEvent({ record: record(), producer, keyId, sign: signer, validateEvent });
  const unsigned = await verifyEvidenceAcceptedEvent({
    event,
    validateEvent,
    expectedTenantId: ids.tenant,
    resolvePublicKey(binding) {
      assert.deepEqual(binding, { tenantId: ids.tenant, producer, keyId, algorithm: "Ed25519" });
      return publicKey;
    },
  });
  assert.deepEqual(unsigned, buildUnsignedEvidenceAcceptedEvent({ record: record(), producer }));
  const tampered = structuredClone(event);
  tampered.payload.sourceSequence += 1;
  await assert.rejects(
    verifyEvidenceAcceptedEvent({ event: tampered, resolvePublicKey: () => publicKey }),
    (error) => error instanceof EvidenceEventError && error.reasonCode === "SOURCE_SIGNATURE_INVALID",
  );
});

test("publisher confirms only an acknowledged stream write and reuses the event ID", async () => {
  const calls = [];
  const publisher = createEvidenceAcceptedPublisher({
    producer,
    keyId,
    sign: signer,
    validateEvent,
    async publish(message) {
      calls.push(["publish", message]);
      return { stream: "TENANT_TRUST_EVENTS", sequence: 72, duplicate: false };
    },
    async markPublished(confirmation) {
      calls.push(["mark", confirmation]);
      return { eventId: confirmation.eventId, status: "published", streamSequence: confirmation.streamSequence, signedEventSha256: confirmation.signedEventSha256 };
    },
    async markFailed() { assert.fail("successful publishing must not record a failure"); },
  });
  const result = await publisher.publishClaim({ context: contextFor(), claim: record() });
  assert.deepEqual(calls.map(([name]) => name), ["publish", "mark"]);
  assert.equal(calls[0][1].messageId, ids.event);
  assert.equal(result.subject, `tenant.${ids.tenant}.events.evidence.accepted.v1`);
});

test("invalid acknowledgement returns the exact claim to retryable state", async () => {
  const failures = [];
  const publisher = createEvidenceAcceptedPublisher({
    producer,
    keyId,
    sign: signer,
    validateEvent,
    publish: async () => ({ stream: "WRONG", sequence: 1, duplicate: false }),
    markPublished: async () => assert.fail("invalid acknowledgement must not confirm the outbox"),
    markFailed: async (failure) => failures.push(failure),
  });
  await assert.rejects(publisher.publishClaim({ context: contextFor(), claim: record() }), /processing failed/u);
  assert.deepEqual(failures[0], {
    tenantId: ids.tenant,
    eventId: ids.event,
    claimToken: ids.claim,
    failureCode: "JETSTREAM_ACK_INVALID",
  });
});

test("consumer verifies before applying one effect across redelivery", async () => {
  const event = await signEvidenceAcceptedEvent({ record: record(), producer, keyId, sign: signer, validateEvent });
  const consumed = new Set();
  let effects = 0;
  const consumer = createEvidenceAcceptedConsumer({
    consumerName: "trust-engine.v1",
    verifyEvent: (options) => verifyEvidenceAcceptedEvent({ ...options, validateEvent }),
    async consumeOnce({ event: delivered, applyEffect }) {
      if (consumed.has(delivered.eventId)) return false;
      await applyEffect({ event: delivered });
      consumed.add(delivered.eventId);
      return true;
    },
  });
  const input = {
    event,
    streamSequence: 72,
    expectedTenantId: ids.tenant,
    resolvePublicKey: () => publicKey,
    applyEffect: async () => { effects += 1; },
  };
  assert.equal((await consumer.consume(input)).applied, true);
  assert.equal((await consumer.consume(input)).applied, false);
  assert.equal(effects, 1);
});

test("PostgreSQL adapters parameterize retry-safe outbox and atomic effect calls", async () => {
  const calls = [];
  const query = async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes("claim_evidence_event_outbox")) return { rows: [] };
    if (sql.includes("mark_evidence_event_published")) {
      return { rows: [{ event_id: ids.event, status: "published", stream_sequence: "72", signed_event_sha256: "cd".repeat(32) }] };
    }
    return { rows: [{ event_id: ids.event, status: "pending" }] };
  };
  const outbox = createPostgresEvidenceEventOutboxRepository({
    query,
    idFactory: () => "018f1234-5678-7abc-8def-0123456789ab",
    clock: () => new Date("2026-10-06T08:00:02.000Z"),
  });
  assert.equal(await outbox.claimNext({ tenantId: ids.tenant, workerId: "publisher.local-1" }), null);
  await outbox.markPublished({ tenantId: ids.tenant, eventId: ids.event, claimToken: ids.claim, streamSequence: 72, signedEventSha256: "cd".repeat(32) });
  await outbox.markFailed({ tenantId: ids.tenant, eventId: ids.event, claimToken: ids.claim, failureCode: "NATS_UNAVAILABLE" });
  assert.equal(calls.every(({ sql }) => sql.includes("$1") && !sql.includes(ids.tenant)), true);

  let effectCalls = 0;
  const effectRepository = createPostgresEvidenceEventEffectRepository({
    clock: () => new Date("2026-10-06T08:00:03.000Z"),
    async withTransaction(work) {
      return work(async (sql, params) => {
        calls.push({ sql, params });
        return { rows: [{ recorded: true }] };
      });
    },
  });
  assert.equal(await effectRepository.consumeOnce({
    consumerName: "trust-engine.v1",
    event: { tenantId: ids.tenant, eventId: ids.event, aggregateId: ids.evidence },
    streamSequence: 72,
    signedEventSha256: "cd".repeat(32),
    applyEffect: async ({ query: transactionQuery }) => {
      effectCalls += 1;
      assert.equal(typeof transactionQuery, "function");
    },
  }), true);
  assert.equal(effectCalls, 1);
});
