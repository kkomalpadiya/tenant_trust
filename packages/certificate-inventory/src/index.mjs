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
const PROFILE_ID = "tenant-client-auth-v1";
const ALGORITHMS = new Set(["ecdsa-p256", "ed25519"]);

export class CertificateInventoryError extends Error {
  constructor(reasonCode) {
    super("Certificate inventory operation denied.");
    this.name = "CertificateInventoryError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new CertificateInventoryError(reasonCode);
}

function requireRecord(value, reasonCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) deny(reasonCode);
  return value;
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
  if (typeof value !== "string" || !value.endsWith("Z")) deny(reasonCode);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) deny(reasonCode);
  return date;
}

function opaqueId(prefix, pattern, idFactory) {
  const uuid = idFactory();
  const value = `${prefix}_${uuid}`;
  if (!pattern.test(value)) deny("GENERATED_ID_INVALID");
  return value;
}

export function createCertificateInventoryIds(idFactory = randomUUID) {
  if (typeof idFactory !== "function") throw new TypeError("An ID factory is required.");
  return Object.freeze({
    certificateId: opaqueId("crt", CERTIFICATE_ID, idFactory),
    eventId: opaqueId("evt", EVENT_ID, idFactory),
    correlationId: opaqueId("cor", CORRELATION_ID, idFactory),
  });
}

export function buildIssuedCertificateRecord({
  context,
  normalizedRequest,
  verifiedCertificate,
  ids = createCertificateInventoryIds(),
} = {}) {
  const trustedContext = requireContext(context);
  const request = requireRecord(normalizedRequest, "ISSUANCE_REQUEST_INVALID");
  const certificate = requireRecord(verifiedCertificate, "VERIFIED_CERTIFICATE_INVALID");
  const identifiers = requireRecord(ids, "INVENTORY_IDS_INVALID");

  if (!CERTIFICATE_ID.test(identifiers.certificateId ?? "")
    || !EVENT_ID.test(identifiers.eventId ?? "")
    || !CORRELATION_ID.test(identifiers.correlationId ?? "")) {
    deny("INVENTORY_IDS_INVALID");
  }
  if (request.operation !== "issue"
    || request.profileId !== PROFILE_ID
    || !REQUEST_ID.test(request.requestId ?? "")
    || !IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "")
    || request.tenantId !== trustedContext.tenantId
    || request.requestedBySubjectId !== trustedContext.subjectId
    || request.subjectId !== certificate.subjectId
    || request.tenantId !== certificate.tenantId
    || request.profileId !== certificate.profileId) {
    deny("ISSUANCE_BINDING_MISMATCH");
  }
  if (!SUBJECT_ID.test(certificate.subjectId ?? "")
    || !ISSUER_ID.test(certificate.issuerId ?? "")
    || !SERIAL.test(certificate.serialNumber ?? "")
    || !SHA256.test(certificate.fingerprintSha256 ?? "")
    || !ALGORITHMS.has(request.proofOfPossession?.publicKeyAlgorithm)) {
    deny("VERIFIED_CERTIFICATE_INVALID");
  }

  const requestedAt = requireUtc(request.requestedAt, "ISSUANCE_TIME_INVALID");
  const notBefore = requireUtc(certificate.notBefore, "CERTIFICATE_VALIDITY_INVALID");
  const notAfter = requireUtc(certificate.notAfter, "CERTIFICATE_VALIDITY_INVALID");
  if (notBefore > requestedAt || requestedAt >= notAfter) deny("CERTIFICATE_VALIDITY_INVALID");

  return Object.freeze({
    schemaVersion: "1.0.0",
    tenantId: trustedContext.tenantId,
    certificateId: identifiers.certificateId,
    subjectId: certificate.subjectId,
    issuerId: certificate.issuerId,
    profileId: certificate.profileId,
    serialNumber: certificate.serialNumber,
    fingerprintSha256: certificate.fingerprintSha256,
    publicKeyAlgorithm: request.proofOfPossession.publicKeyAlgorithm,
    state: "active",
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    issuedAt: request.requestedAt,
    requestedBySubjectId: trustedContext.subjectId,
    requestId: request.requestId,
    idempotencyKey: request.idempotencyKey,
    issuedEventId: identifiers.eventId,
    lastEventId: identifiers.eventId,
    correlationId: identifiers.correlationId,
    supersedesCertificateId: null,
  });
}

export function createCertificateInventoryService({
  insertIssuedCertificate,
  idFactory = randomUUID,
} = {}) {
  if (typeof insertIssuedCertificate !== "function") {
    throw new TypeError("A certificate inventory repository is required.");
  }

  return Object.freeze({
    async recordIssuedCertificate({ context, normalizedRequest, verifiedCertificate } = {}) {
      const record = buildIssuedCertificateRecord({
        context,
        normalizedRequest,
        verifiedCertificate,
        ids: createCertificateInventoryIds(idFactory),
      });
      const persisted = await insertIssuedCertificate(record);
      if (!persisted
        || !CERTIFICATE_ID.test(persisted.certificateId ?? "")
        || !EVENT_ID.test(persisted.eventId ?? "")
        || persisted.state !== "active") {
        deny("INVENTORY_WRITE_UNCONFIRMED");
      }
      return Object.freeze({
        ...verifiedCertificate,
        ...record,
        certificateId: persisted.certificateId,
        issuedEventId: persisted.eventId,
        lastEventId: persisted.eventId,
      });
    },
  });
}
