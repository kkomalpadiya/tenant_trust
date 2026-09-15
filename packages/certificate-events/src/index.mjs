import { createHash, randomUUID, verify as verifySignature } from "node:crypto";
import { EVENT_STREAM, subjectForEvent } from "@tenant-trust/messaging";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const IDEMPOTENCY_KEY = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const CONFIRMATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const CLAIM_TOKEN = /^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const EVENT_TYPE = Object.freeze({
  issued: "certificate.issued.v1",
  renewed: "certificate.renewed.v1",
  superseded: "certificate.superseded.v1",
  revoked: "certificate.revoked.v1",
  expired: "certificate.expired.v1",
});
const STATE = Object.freeze({ issued: "active", renewed: "active", superseded: "superseded", revoked: "revoked", expired: "expired" });

export class CertificateEventError extends Error {
  constructor(reasonCode) {
    super("Certificate lifecycle event processing failed.");
    this.name = "CertificateEventError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new CertificateEventError(reasonCode);
}

function requireRecord(value, reasonCode = "CERTIFICATE_EVENT_INVALID") {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(reasonCode);
  return value;
}

function requireUtc(value, reasonCode = "CERTIFICATE_EVENT_TIME_INVALID") {
  if (typeof value !== "string" || !value.endsWith("Z")) fail(reasonCode);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail(reasonCode);
  return value;
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (value && typeof value === "object" && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
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

function validateLifecycleRecord(record) {
  const value = requireRecord(record);
  if (!TENANT_ID.test(value.tenantId ?? "")
    || !SUBJECT_ID.test(value.subjectId ?? "")
    || !CERTIFICATE_ID.test(value.certificateId ?? "")
    || !ISSUER_ID.test(value.issuerId ?? "")
    || !EVENT_ID.test(value.eventId ?? "")
    || !CORRELATION_ID.test(value.correlationId ?? "")
    || !SERIAL.test(value.serialNumber ?? "")
    || !SHA256.test(value.fingerprintSha256 ?? "")
    || !IDEMPOTENCY_KEY.test(value.idempotencyKey ?? "")
    || !Object.hasOwn(EVENT_TYPE, value.eventType)
    || value.state !== STATE[value.eventType]) fail("CERTIFICATE_EVENT_SOURCE_INVALID");
  requireUtc(value.occurredAt);
  requireUtc(value.recordedAt);
  if (Date.parse(value.recordedAt) < Date.parse(value.occurredAt)) fail("CERTIFICATE_EVENT_TIME_INVALID");
  if (value.actorSubjectId !== null && !SUBJECT_ID.test(value.actorSubjectId ?? "")) fail("CERTIFICATE_EVENT_SOURCE_INVALID");
  if (value.eventType === "issued") {
    if (value.causationId !== null || value.supersedesCertificateId !== null) fail("CERTIFICATE_EVENT_CAUSATION_INVALID");
  } else if (!EVENT_ID.test(value.causationId ?? "")) fail("CERTIFICATE_EVENT_CAUSATION_INVALID");
  if (["issued", "renewed"].includes(value.eventType)) {
    requireUtc(value.notBefore);
    requireUtc(value.notAfter);
    if (Date.parse(value.notBefore) >= Date.parse(value.notAfter)) fail("CERTIFICATE_EVENT_TIME_INVALID");
  }
  if (value.eventType === "renewed" && !CERTIFICATE_ID.test(value.supersedesCertificateId ?? "")) fail("CERTIFICATE_EVENT_CAUSATION_INVALID");
  if (["superseded", "revoked", "expired"].includes(value.eventType) && !REASON_CODE.test(value.reasonCode ?? "")) fail("CERTIFICATE_EVENT_REASON_INVALID");
  if (value.eventType === "expired" && value.reasonCode !== "CERTIFICATE_EXPIRED") fail("CERTIFICATE_EVENT_REASON_INVALID");
  if (value.eventType === "revoked" && !CONFIRMATION_ID.test(value.issuerConfirmationId ?? "")) fail("CERTIFICATE_EVENT_SOURCE_INVALID");
  return value;
}

function validateProducer(producer) {
  const value = requireRecord(producer, "CERTIFICATE_EVENT_PRODUCER_INVALID");
  if (!/^[a-z][a-z0-9-]{1,62}$/u.test(value.service ?? "")
    || typeof value.instanceId !== "string"
    || value.instanceId.length < 1
    || value.instanceId.length > 128
    || Object.keys(value).length !== 2) fail("CERTIFICATE_EVENT_PRODUCER_INVALID");
  return value;
}

export function buildUnsignedCertificateLifecycleEvent({ record, producer } = {}) {
  const source = validateLifecycleRecord(record);
  const trustedProducer = validateProducer(producer);
  const payload = {
    certificateId: source.certificateId,
    issuerId: source.issuerId,
    serialNumber: source.serialNumber,
    fingerprintSha256: source.fingerprintSha256,
    state: source.state,
    actorSubjectId: source.actorSubjectId,
  };
  if (["issued", "renewed"].includes(source.eventType)) {
    payload.notBefore = source.notBefore;
    payload.notAfter = source.notAfter;
    payload.supersedesCertificateId = source.supersedesCertificateId;
  }
  if (source.eventType === "expired") {
    payload.notAfter = requireUtc(source.notAfter);
    payload.reasonCode = source.reasonCode;
  }
  if (["superseded", "revoked"].includes(source.eventType)) payload.reasonCode = source.reasonCode;
  if (source.eventType === "revoked") payload.issuerConfirmationId = source.issuerConfirmationId;

  return deepFreeze({
    schemaVersion: "1.0.0",
    eventId: source.eventId,
    eventType: EVENT_TYPE[source.eventType],
    tenantId: source.tenantId,
    subjectId: source.subjectId,
    aggregateId: source.certificateId,
    correlationId: source.correlationId,
    causationId: source.causationId,
    idempotencyKey: source.idempotencyKey,
    occurredAt: source.occurredAt,
    recordedAt: source.recordedAt,
    producer: { ...trustedProducer },
    payload,
  });
}

function unsignedEvent(event) {
  const value = requireRecord(event);
  const { sourceAuthentication, ...unsigned } = value;
  if (!sourceAuthentication) fail("SOURCE_AUTHENTICATION_INVALID");
  return unsigned;
}

export async function signCertificateLifecycleEvent({ record, producer, keyId, sign, validateEvent } = {}) {
  if (!KEY_ID.test(keyId ?? "") || typeof sign !== "function") fail("SOURCE_SIGNER_INVALID");
  const unsigned = buildUnsignedCertificateLifecycleEvent({ record, producer });
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
  if (validateEvent && validateEvent(event) !== true) fail("CERTIFICATE_EVENT_CONTRACT_INVALID");
  return event;
}

export async function verifyCertificateLifecycleEvent({ event, resolvePublicKey, validateEvent, expectedTenantId } = {}) {
  const value = requireRecord(event);
  if (validateEvent && validateEvent(value) !== true) fail("CERTIFICATE_EVENT_CONTRACT_INVALID");
  if (expectedTenantId !== undefined && value.tenantId !== expectedTenantId) fail("CERTIFICATE_EVENT_TENANT_MISMATCH");
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

export function createCertificateLifecyclePublisher({ producer, keyId, sign, validateEvent, publish, markPublished, markFailed } = {}) {
  validateProducer(producer);
  if (!KEY_ID.test(keyId ?? "")
    || typeof sign !== "function"
    || typeof publish !== "function"
    || typeof markPublished !== "function"
    || typeof markFailed !== "function") throw new TypeError("Signing, publishing and outbox dependencies are required.");

  return Object.freeze({
    async publishClaim({ context, claim } = {}) {
      const claimed = requireRecord(claim, "OUTBOX_CLAIM_INVALID");
      if (!CLAIM_TOKEN.test(claimed.claimToken ?? "")) fail("OUTBOX_CLAIM_INVALID");
      try {
        const event = await signCertificateLifecycleEvent({ record: claimed, producer, keyId, sign, validateEvent });
        const subject = subjectForEvent(context, event);
        const payload = Buffer.from(canonicalizeJson(event), "utf8");
        const acknowledgement = await publish({ subject, payload, messageId: event.eventId });
        if (!acknowledgement
          || acknowledgement.stream !== EVENT_STREAM
          || !Number.isSafeInteger(acknowledgement.sequence)
          || acknowledgement.sequence < 1
          || typeof acknowledgement.duplicate !== "boolean") fail("JETSTREAM_ACK_INVALID");
        const signedEventSha256 = createHash("sha256").update(payload).digest("hex");
        const persisted = await markPublished({
          tenantId: event.tenantId,
          eventId: event.eventId,
          claimToken: claimed.claimToken,
          streamSequence: acknowledgement.sequence,
          signedEventSha256,
        });
        if (!persisted
          || persisted.eventId !== event.eventId
          || persisted.status !== "published"
          || persisted.streamSequence !== acknowledgement.sequence
          || persisted.signedEventSha256 !== signedEventSha256) fail("OUTBOX_CONFIRMATION_INVALID");
        return deepFreeze({ event, subject, acknowledgement: { ...acknowledgement }, signedEventSha256 });
      } catch (error) {
        await markFailed({
          tenantId: claimed.tenantId,
          eventId: claimed.eventId,
          claimToken: claimed.claimToken,
          failureCode: error instanceof CertificateEventError ? error.reasonCode : "CERTIFICATE_EVENT_PUBLISH_FAILED",
        });
        throw error;
      }
    },
  });
}

const CLAIM_SQL = `
SELECT * FROM identity.claim_certificate_event_outbox($1, $2, $3, $4)`;
const MARK_PUBLISHED_SQL = `
SELECT * FROM identity.mark_certificate_event_published($1, $2, $3, $4, $5, $6)`;
const MARK_FAILED_SQL = `
SELECT * FROM identity.mark_certificate_event_publish_failed($1, $2, $3, $4, $5, $6)`;

function rowToClaim(row) {
  if (!row) return null;
  return {
    tenantId: row.tenant_id,
    eventId: row.event_id,
    eventType: row.event_type,
    state: row.certificate_state,
    certificateId: row.certificate_id,
    subjectId: row.subject_id,
    issuerId: row.issuer_id,
    serialNumber: row.serial_number,
    fingerprintSha256: row.fingerprint_sha256,
    notBefore: new Date(row.not_before).toISOString(),
    notAfter: new Date(row.not_after).toISOString(),
    supersedesCertificateId: row.supersedes_certificate_id,
    requestId: row.request_id,
    correlationId: row.correlation_id,
    causationId: row.causation_event_id,
    idempotencyKey: row.idempotency_key,
    actorSubjectId: row.actor_subject_id,
    reasonCode: row.reason_code,
    issuerConfirmationId: row.issuer_confirmation_id,
    occurredAt: new Date(row.occurred_at).toISOString(),
    recordedAt: new Date(row.recorded_at).toISOString(),
    claimToken: row.claim_token,
    attemptCount: Number(row.attempt_count),
  };
}

export function createPostgresCertificateEventOutboxRepository({ query, idFactory = randomUUID, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("A transaction-bound PostgreSQL query function, ID factory and clock are required.");
  }
  return Object.freeze({
    async claimNext({ tenantId, workerId }, { signal } = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !WORKER_ID.test(workerId ?? "")) fail("OUTBOX_CLAIM_INVALID");
      const claimToken = `clm_${idFactory()}`;
      if (!CLAIM_TOKEN.test(claimToken)) fail("OUTBOX_CLAIM_INVALID");
      const claimedAt = clock().toISOString();
      const result = await query(CLAIM_SQL, [tenantId, workerId, claimToken, claimedAt], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) fail("OUTBOX_SOURCE_INVALID");
      return rowToClaim(result.rows[0]);
    },
    async markPublished({ tenantId, eventId, claimToken, streamSequence, signedEventSha256 }, { signal } = {}) {
      const publishedAt = clock().toISOString();
      const result = await query(MARK_PUBLISHED_SQL, [tenantId, eventId, claimToken, streamSequence, signedEventSha256, publishedAt], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail("OUTBOX_CONFIRMATION_INVALID");
      const row = result.rows[0];
      return { eventId: row.event_id, status: row.status, streamSequence: Number(row.stream_sequence), signedEventSha256: row.signed_event_sha256 };
    },
    async markFailed({ tenantId, eventId, claimToken, failureCode }, { signal } = {}) {
      const failedAt = clock().toISOString();
      const result = await query(MARK_FAILED_SQL, [tenantId, eventId, claimToken, failureCode, failedAt, 5], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail("OUTBOX_FAILURE_RECORD_INVALID");
      return { eventId: result.rows[0].event_id, status: result.rows[0].status };
    },
  });
}
