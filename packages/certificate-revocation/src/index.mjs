import { randomUUID } from "node:crypto";
import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const IDEMPOTENCY_KEY = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const CONFIRMATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/u;
const REQUEST_FIELDS = ["certificateId", "idempotencyKey", "reasonCode", "requestId"];

export const REVOCATION_REASON_CODES = Object.freeze({
  KEY_COMPROMISE: "KeyCompromise",
  CA_COMPROMISE: "CACompromise",
  AFFILIATION_CHANGED: "AffiliationChanged",
  SUPERSEDED: "Superseded",
  CESSATION_OF_OPERATION: "CessationOfOperation",
  PRIVILEGE_WITHDRAWN: "PrivilegeWithdrawn",
  AA_COMPROMISE: "AACompromise",
});

export const CERTIFICATE_REVOCATION_DENIAL = Object.freeze({
  statusCode: 403,
  code: "CERTIFICATE_REVOCATION_DENIED",
});

export class CertificateRevocationError extends Error {
  constructor(reasonCode) {
    super("Certificate revocation denied.");
    this.name = "CertificateRevocationError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new CertificateRevocationError(reasonCode);
}

function requireRecord(value, reasonCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) deny(reasonCode);
  return value;
}

function requireExactFields(value, fields, reasonCode) {
  const record = requireRecord(value, reasonCode);
  const actual = Object.keys(record).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) deny(reasonCode);
  return record;
}

function requireContext(context) {
  try {
    return assertNoTenantSwitch(context, []);
  } catch (error) {
    if (error instanceof TenantContextError) deny("TENANT_CONTEXT_INVALID");
    throw error;
  }
}

function requireUtc(value, reasonCode) {
  if (!(value instanceof Date) && typeof value !== "string") deny(reasonCode);
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())
    || (typeof value === "string" && date.toISOString() !== value)) deny(reasonCode);
  return date;
}

function generatedId(prefix, pattern, idFactory) {
  const value = `${prefix}_${idFactory()}`;
  if (!pattern.test(value)) deny("GENERATED_ID_INVALID");
  return value;
}

export function createCertificateRevocationIds(idFactory = randomUUID) {
  if (typeof idFactory !== "function") throw new TypeError("An ID factory is required.");
  return Object.freeze({
    eventId: generatedId("evt", EVENT_ID, idFactory),
    correlationId: generatedId("cor", CORRELATION_ID, idFactory),
  });
}

export function normalizeCertificateRevocationRequest({ context, request, clock = () => new Date() } = {}) {
  const trustedContext = requireContext(context);
  const input = requireExactFields(request, REQUEST_FIELDS, "REQUEST_FIELDS_INVALID");
  if (!REQUEST_ID.test(input.requestId ?? "")) deny("REQUEST_ID_INVALID");
  if (!CERTIFICATE_ID.test(input.certificateId ?? "")) deny("CERTIFICATE_ID_INVALID");
  if (!Object.hasOwn(REVOCATION_REASON_CODES, input.reasonCode)) deny("REVOCATION_REASON_INVALID");
  if (!IDEMPOTENCY_KEY.test(input.idempotencyKey ?? "")) deny("IDEMPOTENCY_KEY_INVALID");
  const requestedAt = requireUtc(clock(), "REVOCATION_TIME_INVALID");
  return Object.freeze({
    schemaVersion: "1.0.0",
    operation: "revoke",
    tenantId: trustedContext.tenantId,
    requestedBySubjectId: trustedContext.subjectId,
    requestedAt: requestedAt.toISOString(),
    requestId: input.requestId,
    certificateId: input.certificateId,
    reasonCode: input.reasonCode,
    caReasonCode: REVOCATION_REASON_CODES[input.reasonCode],
    idempotencyKey: input.idempotencyKey,
  });
}

function validateTarget({ trustedContext, normalizedRequest, certificate }) {
  const target = requireRecord(certificate, "CERTIFICATE_INELIGIBLE");
  if (target.tenantId !== trustedContext.tenantId
    || target.certificateId !== normalizedRequest.certificateId
    || !SUBJECT_ID.test(target.subjectId ?? "")
    || !ISSUER_ID.test(target.issuerId ?? "")
    || !SERIAL.test(target.serialNumber ?? "")
    || !SHA256.test(target.fingerprintSha256 ?? "")
    || !EVENT_ID.test(target.lastEventId ?? "")
    || !Number.isSafeInteger(target.version)
    || target.version < 1
    || target.state !== "active") {
    deny("CERTIFICATE_INELIGIBLE");
  }
  if (target.subjectId !== trustedContext.subjectId
    && !trustedContext.roles.includes("tenant-admin")) deny("CERTIFICATE_REVOCATION_UNAUTHORIZED");
  return target;
}

async function requireIssuer({ trustedContext, target, resolveIssuer }) {
  if (typeof resolveIssuer !== "function") throw new TypeError("An issuer repository is required.");
  const issuer = await resolveIssuer({ tenantId: trustedContext.tenantId });
  if (!issuer
    || issuer.tenantId !== trustedContext.tenantId
    || issuer.issuerId !== target.issuerId
    || issuer.state !== "active"
    || !Array.isArray(issuer.allowedCertificateOperations)
    || !issuer.allowedCertificateOperations.includes("revoke")
    || typeof issuer.authorityUrl !== "string"
    || !/^https:\/\/[^\s]+$/u.test(issuer.authorityUrl)) {
    deny("ACTIVE_ISSUER_REQUIRED");
  }
  return issuer;
}

async function prepareNormalizedRevocation({ trustedContext, normalizedRequest, loadCertificate, resolveIssuer }) {
  if (typeof loadCertificate !== "function") throw new TypeError("A certificate repository is required.");
  const target = validateTarget({
    trustedContext,
    normalizedRequest,
    certificate: await loadCertificate({
      tenantId: trustedContext.tenantId,
      certificateId: normalizedRequest.certificateId,
    }),
  });
  const issuer = await requireIssuer({ trustedContext, target, resolveIssuer });
  const revocationInstruction = Object.freeze({
    operation: "revoke",
    tenantId: trustedContext.tenantId,
    certificateId: target.certificateId,
    subjectId: target.subjectId,
    issuerId: target.issuerId,
    serialNumber: target.serialNumber,
    fingerprintSha256: target.fingerprintSha256,
    reasonCode: normalizedRequest.reasonCode,
    caReasonCode: normalizedRequest.caReasonCode,
    requestId: normalizedRequest.requestId,
    idempotencyKey: normalizedRequest.idempotencyKey,
    requestedAt: normalizedRequest.requestedAt,
    authorityUrl: issuer.authorityUrl,
  });
  return Object.freeze({ normalizedRequest, target, issuer, revocationInstruction });
}

export async function prepareCertificateRevocation({
  context,
  request,
  loadCertificate,
  resolveIssuer,
  clock = () => new Date(),
} = {}) {
  const trustedContext = requireContext(context);
  const normalizedRequest = normalizeCertificateRevocationRequest({ context: trustedContext, request, clock });
  return prepareNormalizedRevocation({ trustedContext, normalizedRequest, loadCertificate, resolveIssuer });
}

function validateReplay(existing, normalizedRequest) {
  if (!existing
    || existing.tenantId !== normalizedRequest.tenantId
    || existing.certificateId !== normalizedRequest.certificateId
    || existing.requestId !== normalizedRequest.requestId
    || existing.reasonCode !== normalizedRequest.reasonCode
    || existing.requestedBySubjectId !== normalizedRequest.requestedBySubjectId
    || !EVENT_ID.test(existing.eventId ?? "")
    || !CORRELATION_ID.test(existing.correlationId ?? "")
    || !CONFIRMATION_ID.test(existing.issuerConfirmationId ?? "")
    || existing.state !== "revoked"
    || !Number.isSafeInteger(existing.version)
    || existing.version < 2) deny("IDEMPOTENCY_CONFLICT");
  return Object.freeze({ ...existing, replayed: true });
}

function validateIssuerConfirmation(confirmation, prepared, checkedAt) {
  const value = requireRecord(confirmation, "ISSUER_CONFIRMATION_INVALID");
  const expected = prepared.revocationInstruction;
  if (value.status !== "revoked"
    || value.tenantId !== expected.tenantId
    || value.certificateId !== expected.certificateId
    || value.issuerId !== expected.issuerId
    || value.serialNumber !== expected.serialNumber
    || value.fingerprintSha256 !== expected.fingerprintSha256
    || value.reasonCode !== expected.reasonCode
    || !CONFIRMATION_ID.test(value.issuerConfirmationId ?? "")) {
    deny("ISSUER_CONFIRMATION_INVALID");
  }
  const revokedAt = requireUtc(value.revokedAt, "ISSUER_CONFIRMATION_INVALID");
  if (revokedAt < new Date(expected.requestedAt)
    || revokedAt.getTime() > checkedAt.getTime() + 2_000) deny("ISSUER_CONFIRMATION_INVALID");
  return { ...value, revokedAt: revokedAt.toISOString() };
}

export function createCertificateRevocationService({
  loadCertificate,
  loadExistingRevocation,
  resolveIssuer,
  revokeAtIssuer,
  recordRevocation,
  idFactory = randomUUID,
  clock = () => new Date(),
} = {}) {
  if (typeof loadExistingRevocation !== "function"
    || typeof revokeAtIssuer !== "function"
    || typeof recordRevocation !== "function") {
    throw new TypeError("Revocation lookup, issuer and persistence dependencies are required.");
  }

  return Object.freeze({
    async revoke({ context, request } = {}) {
      const trustedContext = requireContext(context);
      const normalizedRequest = normalizeCertificateRevocationRequest({ context: trustedContext, request, clock });
      const existing = await loadExistingRevocation({
        tenantId: trustedContext.tenantId,
        idempotencyKey: normalizedRequest.idempotencyKey,
      });
      if (existing) return validateReplay(existing, normalizedRequest);

      const prepared = await prepareNormalizedRevocation({
        trustedContext,
        normalizedRequest,
        loadCertificate,
        resolveIssuer,
      });
      const confirmation = validateIssuerConfirmation(
        await revokeAtIssuer(prepared.revocationInstruction),
        prepared,
        requireUtc(clock(), "REVOCATION_TIME_INVALID"),
      );
      const identifiers = createCertificateRevocationIds(idFactory);
      const record = Object.freeze({
        schemaVersion: "1.0.0",
        tenantId: trustedContext.tenantId,
        certificateId: prepared.target.certificateId,
        subjectId: prepared.target.subjectId,
        issuerId: prepared.target.issuerId,
        serialNumber: prepared.target.serialNumber,
        fingerprintSha256: prepared.target.fingerprintSha256,
        requestId: normalizedRequest.requestId,
        idempotencyKey: normalizedRequest.idempotencyKey,
        reasonCode: normalizedRequest.reasonCode,
        requestedBySubjectId: trustedContext.subjectId,
        revokedAt: confirmation.revokedAt,
        issuerConfirmationId: confirmation.issuerConfirmationId,
        eventId: identifiers.eventId,
        correlationId: identifiers.correlationId,
        causationEventId: prepared.target.lastEventId,
        expectedVersion: prepared.target.version,
      });
      const persisted = await recordRevocation(record);
      if (!persisted
        || persisted.certificateId !== record.certificateId
        || !EVENT_ID.test(persisted.eventId ?? "")
        || !CORRELATION_ID.test(persisted.correlationId ?? "")
        || persisted.state !== "revoked"
        || !Number.isSafeInteger(persisted.version)
        || persisted.version < record.expectedVersion + 1) deny("REVOCATION_WRITE_UNCONFIRMED");
      return Object.freeze({
        tenantId: record.tenantId,
        certificateId: record.certificateId,
        subjectId: record.subjectId,
        issuerId: record.issuerId,
        serialNumber: record.serialNumber,
        fingerprintSha256: record.fingerprintSha256,
        state: "revoked",
        reasonCode: record.reasonCode,
        revokedAt: record.revokedAt,
        issuerConfirmationId: record.issuerConfirmationId,
        eventId: persisted.eventId,
        correlationId: persisted.correlationId,
        version: persisted.version,
        replayed: false,
      });
    },
  });
}

const LOAD_CERTIFICATE_SQL = `
SELECT tenant_id, certificate_id, subject_id, issuer_id, serial_number,
       fingerprint_sha256, state, last_event_id, version
FROM identity.certificates
WHERE tenant_id = $1 AND certificate_id = $2
LIMIT 1`;

const LOAD_REVOCATION_SQL = `
SELECT event.tenant_id, event.certificate_id, event.event_id,
       event.correlation_id, event.request_id, event.reason_code,
       event.actor_subject_id, event.issuer_confirmation_id,
       event.occurred_at, certificate.state, certificate.version
FROM identity.certificate_lifecycle_events AS event
JOIN identity.certificates AS certificate
  ON certificate.tenant_id = event.tenant_id
 AND certificate.certificate_id = event.certificate_id
WHERE event.tenant_id = $1
  AND event.idempotency_key = $2
  AND event.event_type = 'revoked'
LIMIT 1`;

const RECORD_REVOCATION_SQL = `
SELECT recorded_certificate_id, recorded_event_id, recorded_correlation_id,
       recorded_state, recorded_version
FROM identity.record_certificate_revocation($1, $2, $3, $4, $5, $6, $7, $8)`;

export function createPostgresCertificateRevocationRepository({ query } = {}) {
  if (typeof query !== "function") throw new TypeError("A transaction-bound PostgreSQL query function is required.");
  return Object.freeze({
    async loadCertificate({ tenantId, certificateId }, { signal } = {}) {
      const result = await query(LOAD_CERTIFICATE_SQL, [tenantId, certificateId], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) deny("REVOCATION_SOURCE_INVALID");
      const row = result.rows[0];
      if (!row) return null;
      return {
        tenantId: row.tenant_id,
        certificateId: row.certificate_id,
        subjectId: row.subject_id,
        issuerId: row.issuer_id,
        serialNumber: row.serial_number,
        fingerprintSha256: row.fingerprint_sha256,
        state: row.state,
        lastEventId: row.last_event_id,
        version: Number(row.version),
      };
    },
    async loadExistingRevocation({ tenantId, idempotencyKey }, { signal } = {}) {
      const result = await query(LOAD_REVOCATION_SQL, [tenantId, idempotencyKey], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) deny("REVOCATION_SOURCE_INVALID");
      const row = result.rows[0];
      if (!row) return null;
      return {
        tenantId: row.tenant_id,
        certificateId: row.certificate_id,
        eventId: row.event_id,
        correlationId: row.correlation_id,
        requestId: row.request_id,
        reasonCode: row.reason_code,
        requestedBySubjectId: row.actor_subject_id,
        issuerConfirmationId: row.issuer_confirmation_id,
        revokedAt: requireUtc(row.occurred_at, "REVOCATION_SOURCE_INVALID").toISOString(),
        state: row.state,
        version: Number(row.version),
      };
    },
    async recordRevocation(record, { signal } = {}) {
      const result = await query(RECORD_REVOCATION_SQL, [
        record.eventId,
        record.correlationId,
        record.requestId,
        record.certificateId,
        record.reasonCode,
        record.revokedAt,
        record.idempotencyKey,
        record.issuerConfirmationId,
      ], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) deny("REVOCATION_WRITE_UNCONFIRMED");
      const row = result.rows[0];
      return {
        certificateId: row.recorded_certificate_id,
        eventId: row.recorded_event_id,
        correlationId: row.recorded_correlation_id,
        state: row.recorded_state,
        version: Number(row.recorded_version),
      };
    },
  });
}

export function certificateRevocationSafeDenial(error) {
  if (!(error instanceof CertificateRevocationError)) throw error;
  return CERTIFICATE_REVOCATION_DENIAL;
}
