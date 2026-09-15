import assert from "node:assert/strict";
import { generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CertificateEventError,
  buildUnsignedCertificateLifecycleEvent,
  canonicalizeJson,
  createCertificateLifecyclePublisher,
  createPostgresCertificateEventOutboxRepository,
  signCertificateLifecycleEvent,
  verifyCertificateLifecycleEvent,
} from "../src/index.mjs";

const schemaRoot = resolve(import.meta.dirname, "../../contracts/schemas");
const common = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const certificateSchema = JSON.parse(readFileSync(resolve(schemaRoot, "events/certificate-event.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateEvent = ajv.compile(certificateSchema);

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  predecessor: "crt_018f1234-5678-7abc-8def-0123456789ac",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
  event: "evt_018f1234-5678-7abc-8def-0123456789ab",
  cause: "evt_018f1234-5678-7abc-8def-0123456789ac",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
};
const producer = { service: "certificate-events", instanceId: "test-1" };
const keyId = "certificate-events:key-2026-01";
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = (content) => ed25519Sign(null, content, privateKey);

function record(overrides = {}) {
  return {
    tenantId: ids.tenant,
    eventId: ids.event,
    eventType: "issued",
    state: "active",
    certificateId: ids.certificate,
    subjectId: ids.subject,
    issuerId: ids.issuer,
    serialNumber: "01AF".padEnd(32, "0"),
    fingerprintSha256: "ab".repeat(32),
    notBefore: "2026-09-15T10:00:00.000Z",
    notAfter: "2026-10-15T10:00:00.000Z",
    supersedesCertificateId: null,
    requestId: "req_018f1234-5678-7abc-8def-0123456789ab",
    correlationId: ids.correlation,
    causationId: null,
    idempotencyKey: "tenant-alpha:certificate:event:test-1",
    actorSubjectId: ids.subject,
    reasonCode: null,
    issuerConfirmationId: null,
    occurredAt: "2026-09-15T10:00:00.000Z",
    recordedAt: "2026-09-15T10:00:01.000Z",
    claimToken: "clm_018f1234-5678-7abc-8def-0123456789ab",
    attemptCount: 1,
    ...overrides,
  };
}

function contextFor(tenantId = ids.tenant) {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "certificate-event-test", tenantId, subjectId: ids.subject },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: { tenantId, subjectId: ids.subject, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

test("canonical JSON is stable across object insertion order", () => {
  assert.equal(canonicalizeJson({ z: 1, a: { y: 2, x: [3, true] } }), '{"a":{"x":[3,true],"y":2},"z":1}');
  assert.equal(canonicalizeJson({ a: { x: [3, true], y: 2 }, z: 1 }), canonicalizeJson({ z: 1, a: { y: 2, x: [3, true] } }));
});

test("issued, renewed, revoked and expired records build contract-valid causal payloads", async () => {
  const cases = [
    record(),
    record({ eventType: "renewed", causationId: ids.cause, supersedesCertificateId: ids.predecessor }),
    record({ eventType: "revoked", state: "revoked", causationId: ids.cause, reasonCode: "KEY_COMPROMISE", issuerConfirmationId: "step-ca:revocation:test-0001" }),
    record({ eventType: "expired", state: "expired", causationId: ids.cause, reasonCode: "CERTIFICATE_EXPIRED" }),
  ];
  for (const source of cases) {
    const event = await signCertificateLifecycleEvent({ record: source, producer, keyId, sign: signer, validateEvent });
    assert.equal(validateEvent(event), true, ajv.errorsText(validateEvent.errors));
    assert.equal(event.causationId, source.causationId);
    assert.equal(event.payload.actorSubjectId, ids.subject);
  }
});

test("signatures verify only for the bound tenant, producer key and unchanged content", async () => {
  const event = await signCertificateLifecycleEvent({ record: record(), producer, keyId, sign: signer, validateEvent });
  const unsigned = await verifyCertificateLifecycleEvent({
    event,
    validateEvent,
    expectedTenantId: ids.tenant,
    resolvePublicKey(binding) {
      assert.deepEqual(binding, { tenantId: ids.tenant, producer, keyId, algorithm: "Ed25519" });
      return publicKey;
    },
  });
  assert.deepEqual(unsigned, buildUnsignedCertificateLifecycleEvent({ record: record(), producer }));

  const tampered = structuredClone(event);
  tampered.payload.state = "revoked";
  await assert.rejects(
    verifyCertificateLifecycleEvent({ event: tampered, resolvePublicKey: () => publicKey }),
    (error) => error instanceof CertificateEventError && error.reasonCode === "SOURCE_SIGNATURE_INVALID",
  );
  await assert.rejects(
    verifyCertificateLifecycleEvent({ event, expectedTenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac", resolvePublicKey: () => publicKey }),
    (error) => error instanceof CertificateEventError && error.reasonCode === "CERTIFICATE_EVENT_TENANT_MISMATCH",
  );
});

test("malformed causal and source fields fail before signing", async () => {
  await assert.rejects(signCertificateLifecycleEvent({ record: record({ eventType: "renewed", causationId: null }), producer, keyId, sign: signer }), /processing failed/u);
  await assert.rejects(signCertificateLifecycleEvent({ record: record(), producer, keyId: "bad", sign: signer }), /processing failed/u);
  await assert.rejects(signCertificateLifecycleEvent({ record: record(), producer, keyId, sign: () => Buffer.alloc(12) }), /processing failed/u);
});

test("publisher waits for JetStream acknowledgement before confirming the outbox", async () => {
  const calls = [];
  const publisher = createCertificateLifecyclePublisher({
    producer,
    keyId,
    sign: signer,
    validateEvent,
    async publish(message) {
      calls.push(["publish", message]);
      return { stream: "TENANT_TRUST_EVENTS", sequence: 41, duplicate: false };
    },
    async markPublished(confirmation) {
      calls.push(["mark", confirmation]);
      return { eventId: confirmation.eventId, status: "published", streamSequence: confirmation.streamSequence, signedEventSha256: confirmation.signedEventSha256 };
    },
    async markFailed() {
      assert.fail("successful publishing must not record a failure");
    },
  });
  const result = await publisher.publishClaim({ context: contextFor(), claim: record() });
  assert.equal(calls[0][0], "publish");
  assert.equal(calls[1][0], "mark");
  assert.equal(calls[0][1].messageId, ids.event);
  assert.equal(result.subject, `tenant.${ids.tenant}.events.certificate.issued.v1`);
});

test("publisher records a bounded retry failure and never confirms an invalid acknowledgement", async () => {
  const failures = [];
  const publisher = createCertificateLifecyclePublisher({
    producer,
    keyId,
    sign: signer,
    validateEvent,
    publish: async () => ({ stream: "WRONG", sequence: 1, duplicate: false }),
    markPublished: async () => assert.fail("invalid acknowledgement must not confirm the outbox"),
    markFailed: async (failure) => failures.push(failure),
  });
  await assert.rejects(publisher.publishClaim({ context: contextFor(), claim: record() }), /processing failed/u);
  assert.equal(failures[0].failureCode, "JETSTREAM_ACK_INVALID");
});

test("publisher rejects a context tenant switch before durable confirmation", async () => {
  let marked = false;
  const publisher = createCertificateLifecyclePublisher({
    producer,
    keyId,
    sign: signer,
    validateEvent,
    publish: async () => assert.fail("tenant mismatch must not publish"),
    markPublished: async () => { marked = true; },
    markFailed: async () => {},
  });
  await assert.rejects(publisher.publishClaim({ context: contextFor("tnt_018f1234-5678-7abc-8def-0123456789ac"), claim: record() }));
  assert.equal(marked, false);
});

test("PostgreSQL adapter uses parameterized claim, success and retry functions", async () => {
  const calls = [];
  const query = async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes("claim_certificate_event_outbox")) return { rows: [] };
    if (sql.includes("mark_certificate_event_published")) return { rows: [{ event_id: ids.event, status: "published", stream_sequence: "9", signed_event_sha256: "cd".repeat(32) }] };
    return { rows: [{ event_id: ids.event, status: "pending" }] };
  };
  const repository = createPostgresCertificateEventOutboxRepository({
    query,
    idFactory: () => "018f1234-5678-7abc-8def-0123456789ab",
    clock: () => new Date("2026-09-15T10:00:02.000Z"),
  });
  assert.equal(await repository.claimNext({ tenantId: ids.tenant, workerId: "publisher.local-1" }), null);
  await repository.markPublished({ tenantId: ids.tenant, eventId: ids.event, claimToken: record().claimToken, streamSequence: 9, signedEventSha256: "cd".repeat(32) });
  await repository.markFailed({ tenantId: ids.tenant, eventId: ids.event, claimToken: record().claimToken, failureCode: "NATS_UNAVAILABLE" });
  assert.deepEqual(calls[0].params, [ids.tenant, "publisher.local-1", record().claimToken, "2026-09-15T10:00:02.000Z"]);
  assert.equal(calls.every((call) => !call.sql.includes(ids.tenant) && call.sql.includes("$1")), true);
});
