import { createHash, randomUUID, verify as verifySignature } from "node:crypto";
import { EVENT_STREAM, subjectForEvent } from "@tenant-trust/messaging";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SOURCE_ID = /^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const CLAIM_TOKEN = /^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const CONSUMER_NAME = WORKER_ID;
const EVIDENCE_TYPES = new Set(["identity", "device", "behaviour", "certificate", "compliance"]);

export class EvidenceEventError extends Error {
  constructor(reasonCode) {
    super("Accepted evidence event processing failed.");
    this.name = "EvidenceEventError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new EvidenceEventError(reasonCode);
}

function requireRecord(value, reasonCode = "EVIDENCE_EVENT_INVALID") {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(reasonCode);
  return value;
}

function requireUtc(value, reasonCode = "EVIDENCE_EVENT_TIME_INVALID") {
  if (typeof value !== "string" || !value.endsWith("Z")) fail(reasonCode);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail(reasonCode);
  return value;
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (value && typeof value === "object"
      && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`).join(",")}}`;
  }
  fail("CANONICAL_CONTENT_INVALID");
}

export function canonicalizeJson(value) {
  return canonicalValue(value);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function validateProducer(producer) {
  const value = requireRecord(producer, "EVIDENCE_EVENT_PRODUCER_INVALID");
  if (!/^[a-z][a-z0-9-]{1,62}$/u.test(value.service ?? "")
      || typeof value.instanceId !== "string"
      || value.instanceId.length < 1
      || value.instanceId.length > 128
      || Object.keys(value).length !== 2) fail("EVIDENCE_EVENT_PRODUCER_INVALID");
  return value;
}

function validateAcceptedRecord(record) {
  const value = requireRecord(record);
  if (!TENANT_ID.test(value.tenantId ?? "")
      || !SUBJECT_ID.test(value.subjectId ?? "")
      || !SOURCE_ID.test(value.sourceId ?? "")
      || !EVIDENCE_ID.test(value.evidenceId ?? "")
      || !EVENT_ID.test(value.eventId ?? "")
      || !EVENT_ID.test(value.sourceEventId ?? "")
      || !CORRELATION_ID.test(value.correlationId ?? "")
      || !EVIDENCE_TYPES.has(value.evidenceType)
      || !Number.isSafeInteger(value.sourceSequence)
      || value.sourceSequence < 0
      || !SHA256.test(value.contentHashSha256 ?? "")
      || typeof value.synthetic !== "boolean") fail("EVIDENCE_EVENT_SOURCE_INVALID");
  for (const field of ["observedAt", "expiresAt", "acceptedAt"]) requireUtc(value[field]);
  if (Date.parse(value.observedAt) >= Date.parse(value.expiresAt)
      || Date.parse(value.acceptedAt) < Date.parse(value.observedAt)
      || Date.parse(value.acceptedAt) >= Date.parse(value.expiresAt)) fail("EVIDENCE_EVENT_TIME_INVALID");
  return value;
}

export function buildUnsignedEvidenceAcceptedEvent({ record, producer } = {}) {
  const source = validateAcceptedRecord(record);
  const trustedProducer = validateProducer(producer);
  return deepFreeze({
    schemaVersion: "1.0.0",
    eventId: source.eventId,
    eventType: "evidence.accepted.v1",
    tenantId: source.tenantId,
    subjectId: source.subjectId,
    aggregateId: source.evidenceId,
    correlationId: source.correlationId,
    causationId: source.sourceEventId,
    idempotencyKey: `evidence-accepted:${source.evidenceId}`,
    occurredAt: source.acceptedAt,
    recordedAt: source.acceptedAt,
    producer: { ...trustedProducer },
    payload: {
      evidenceId: source.evidenceId,
      sourceId: source.sourceId,
      evidenceType: source.evidenceType,
      observedAt: source.observedAt,
      expiresAt: source.expiresAt,
      sourceSequence: source.sourceSequence,
      contentHashSha256: source.contentHashSha256,
      synthetic: source.synthetic,
    },
  });
}

function unsignedEvent(event) {
  const value = requireRecord(event);
  const { sourceAuthentication, ...unsigned } = value;
  if (!sourceAuthentication) fail("SOURCE_AUTHENTICATION_INVALID");
  return unsigned;
}

export async function signEvidenceAcceptedEvent({ record, producer, keyId, sign, validateEvent } = {}) {
  if (!KEY_ID.test(keyId ?? "") || typeof sign !== "function") fail("SOURCE_SIGNER_INVALID");
  const unsigned = buildUnsignedEvidenceAcceptedEvent({ record, producer });
  const content = Buffer.from(canonicalizeJson(unsigned), "utf8");
  const digest = createHash("sha256").update(content).digest("hex");
  const signature = Buffer.from(await sign(content, { algorithm: "Ed25519", keyId, tenantId: unsigned.tenantId }));
  if (signature.length !== 64) fail("SOURCE_SIGNATURE_INVALID");
  const event = deepFreeze({
    ...unsigned,
    sourceAuthentication: {
      algorithm: "Ed25519",
      canonicalization: "tenant-trust-json-v1",
      keyId,
      signedContentSha256: digest,
      signatureBase64Url: signature.toString("base64url"),
    },
  });
  if (validateEvent && validateEvent(event) !== true) fail("EVIDENCE_EVENT_CONTRACT_INVALID");
  return event;
}

export async function verifyEvidenceAcceptedEvent({ event, resolvePublicKey, validateEvent, expectedTenantId } = {}) {
  const value = requireRecord(event);
  if (validateEvent && validateEvent(value) !== true) fail("EVIDENCE_EVENT_CONTRACT_INVALID");
  if (value.eventType !== "evidence.accepted.v1") fail("EVIDENCE_EVENT_TYPE_INVALID");
  if (value.aggregateId !== value.payload?.evidenceId) fail("EVIDENCE_EVENT_BINDING_INVALID");
  if (expectedTenantId !== undefined && value.tenantId !== expectedTenantId) fail("EVIDENCE_EVENT_TENANT_MISMATCH");
  const authentication = requireRecord(value.sourceAuthentication, "SOURCE_AUTHENTICATION_INVALID");
  if (authentication.algorithm !== "Ed25519"
      || authentication.canonicalization !== "tenant-trust-json-v1"
      || !KEY_ID.test(authentication.keyId ?? "")
      || !SHA256.test(authentication.signedContentSha256 ?? "")
      || !/^[A-Za-z0-9_-]{86}$/u.test(authentication.signatureBase64Url ?? "")
      || typeof resolvePublicKey !== "function") fail("SOURCE_AUTHENTICATION_INVALID");
  const unsigned = unsignedEvent(value);
  const content = Buffer.from(canonicalizeJson(unsigned), "utf8");
  const digest = createHash("sha256").update(content).digest("hex");
  if (digest !== authentication.signedContentSha256) fail("SOURCE_SIGNATURE_INVALID");
  const publicKey = await resolvePublicKey({
    tenantId: value.tenantId,
    producer: value.producer,
    keyId: authentication.keyId,
    algorithm: authentication.algorithm,
  });
  if (!publicKey || !verifySignature(null, content, publicKey, Buffer.from(authentication.signatureBase64Url, "base64url"))) {
    fail("SOURCE_SIGNATURE_INVALID");
  }
  return deepFreeze(structuredClone(unsigned));
}

export function createEvidenceAcceptedPublisher({ producer, keyId, sign, validateEvent, publish, markPublished, markFailed } = {}) {
  validateProducer(producer);
  if (!KEY_ID.test(keyId ?? "") || typeof sign !== "function" || typeof publish !== "function"
      || typeof markPublished !== "function" || typeof markFailed !== "function") {
    throw new TypeError("Signing, publishing and outbox dependencies are required.");
  }
  return Object.freeze({
    async publishClaim({ context, claim } = {}) {
      const claimed = requireRecord(claim, "OUTBOX_CLAIM_INVALID");
      if (!CLAIM_TOKEN.test(claimed.claimToken ?? "")) fail("OUTBOX_CLAIM_INVALID");
      try {
        const event = await signEvidenceAcceptedEvent({ record: claimed, producer, keyId, sign, validateEvent });
        const subject = subjectForEvent(context, event);
        const payload = Buffer.from(canonicalizeJson(event), "utf8");
        const acknowledgement = await publish({ subject, payload, messageId: event.eventId });
        if (!acknowledgement || acknowledgement.stream !== EVENT_STREAM
            || !Number.isSafeInteger(acknowledgement.sequence) || acknowledgement.sequence < 1
            || typeof acknowledgement.duplicate !== "boolean") fail("JETSTREAM_ACK_INVALID");
        const signedEventSha256 = createHash("sha256").update(payload).digest("hex");
        const persisted = await markPublished({
          tenantId: event.tenantId,
          eventId: event.eventId,
          claimToken: claimed.claimToken,
          streamSequence: acknowledgement.sequence,
          signedEventSha256,
        });
        if (!persisted || persisted.eventId !== event.eventId || persisted.status !== "published"
            || persisted.streamSequence !== acknowledgement.sequence
            || persisted.signedEventSha256 !== signedEventSha256) fail("OUTBOX_CONFIRMATION_INVALID");
        return deepFreeze({ event, subject, acknowledgement: { ...acknowledgement }, signedEventSha256 });
      } catch (error) {
        await markFailed({
          tenantId: claimed.tenantId,
          eventId: claimed.eventId,
          claimToken: claimed.claimToken,
          failureCode: error instanceof EvidenceEventError ? error.reasonCode : "EVIDENCE_EVENT_PUBLISH_FAILED",
        });
        throw error;
      }
    },
  });
}

export function createEvidenceAcceptedConsumer({ consumerName, verifyEvent, consumeOnce } = {}) {
  if (!CONSUMER_NAME.test(consumerName ?? "") || typeof verifyEvent !== "function" || typeof consumeOnce !== "function") {
    throw new TypeError("A valid consumer name, event verifier and atomic consume-once function are required.");
  }
  return Object.freeze({
    async consume({ event, streamSequence, expectedTenantId, resolvePublicKey, applyEffect } = {}) {
      if (!Number.isSafeInteger(streamSequence) || streamSequence < 1 || typeof applyEffect !== "function") {
        fail("EVIDENCE_EVENT_DELIVERY_INVALID");
      }
      const verified = await verifyEvent({ event, expectedTenantId, resolvePublicKey });
      const signedEventSha256 = createHash("sha256")
        .update(Buffer.from(canonicalizeJson(event), "utf8"))
        .digest("hex");
      const applied = await consumeOnce({
        consumerName,
        event,
        verified,
        streamSequence,
        signedEventSha256,
        applyEffect,
      });
      if (typeof applied !== "boolean") fail("EVIDENCE_EVENT_EFFECT_INVALID");
      return deepFreeze({ applied, eventId: event.eventId, signedEventSha256 });
    },
  });
}

const CLAIM_SQL = `SELECT * FROM trust.claim_evidence_event_outbox($1, $2, $3, $4)`;
const MARK_PUBLISHED_SQL = `SELECT * FROM trust.mark_evidence_event_published($1, $2, $3, $4, $5, $6)`;
const MARK_FAILED_SQL = `SELECT * FROM trust.mark_evidence_event_publish_failed($1, $2, $3, $4, $5, $6)`;
const RECORD_EFFECT_SQL = `SELECT trust.record_evidence_event_effect($1, $2, $3, $4, $5, $6, $7) AS recorded`;

function rowToClaim(row) {
  if (!row) return null;
  return {
    tenantId: row.tenant_id,
    eventId: row.event_id,
    sourceEventId: row.source_event_id,
    evidenceId: row.evidence_id,
    correlationId: row.correlation_id,
    subjectId: row.subject_id,
    sourceId: row.source_id,
    evidenceType: row.evidence_type,
    sourceSequence: Number(row.source_sequence),
    contentHashSha256: row.content_hash_sha256,
    synthetic: row.synthetic,
    observedAt: new Date(row.observed_at).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
    acceptedAt: new Date(row.accepted_at).toISOString(),
    claimToken: row.claim_token,
    attemptCount: Number(row.attempt_count),
  };
}

export function createPostgresEvidenceEventOutboxRepository({ query, idFactory = randomUUID, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("A transaction-bound PostgreSQL query function, ID factory and clock are required.");
  }
  return Object.freeze({
    async claimNext({ tenantId, workerId }, { signal } = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !WORKER_ID.test(workerId ?? "")) fail("OUTBOX_CLAIM_INVALID");
      const claimToken = `clm_${idFactory()}`;
      if (!CLAIM_TOKEN.test(claimToken)) fail("OUTBOX_CLAIM_INVALID");
      const result = await query(CLAIM_SQL, [tenantId, workerId, claimToken, clock().toISOString()], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) fail("OUTBOX_SOURCE_INVALID");
      return rowToClaim(result.rows[0]);
    },
    async markPublished({ tenantId, eventId, claimToken, streamSequence, signedEventSha256 }, { signal } = {}) {
      const result = await query(MARK_PUBLISHED_SQL,
        [tenantId, eventId, claimToken, streamSequence, signedEventSha256, clock().toISOString()], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail("OUTBOX_CONFIRMATION_INVALID");
      const row = result.rows[0];
      return { eventId: row.event_id, status: row.status, streamSequence: Number(row.stream_sequence), signedEventSha256: row.signed_event_sha256 };
    },
    async markFailed({ tenantId, eventId, claimToken, failureCode }, { signal } = {}) {
      const result = await query(MARK_FAILED_SQL,
        [tenantId, eventId, claimToken, failureCode, clock().toISOString(), 5], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail("OUTBOX_FAILURE_RECORD_INVALID");
      return { eventId: result.rows[0].event_id, status: result.rows[0].status };
    },
  });
}

export function createPostgresEvidenceEventEffectRepository({ withTransaction, clock = () => new Date() } = {}) {
  if (typeof withTransaction !== "function" || typeof clock !== "function") {
    throw new TypeError("A PostgreSQL transaction boundary and clock are required.");
  }
  return Object.freeze({
    async consumeOnce({ consumerName, event, streamSequence, signedEventSha256, applyEffect }) {
      if (!CONSUMER_NAME.test(consumerName ?? "") || !TENANT_ID.test(event?.tenantId ?? "")
          || !EVENT_ID.test(event?.eventId ?? "") || !EVIDENCE_ID.test(event?.aggregateId ?? "")
          || !Number.isSafeInteger(streamSequence) || streamSequence < 1
          || !SHA256.test(signedEventSha256 ?? "") || typeof applyEffect !== "function") {
        fail("EVIDENCE_EVENT_EFFECT_INVALID");
      }
      return withTransaction(async (query) => {
        const result = await query(RECORD_EFFECT_SQL, [
          consumerName, event.tenantId, event.eventId, event.aggregateId,
          streamSequence, signedEventSha256, clock().toISOString(),
        ]);
        if (!result || !Array.isArray(result.rows) || result.rows.length !== 1
            || typeof result.rows[0].recorded !== "boolean") fail("EVIDENCE_EVENT_EFFECT_INVALID");
        if (!result.rows[0].recorded) return false;
        await applyEffect({ event, query });
        return true;
      });
    },
  });
}
