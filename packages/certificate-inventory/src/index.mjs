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
  const value = `${prefix}_${idFactory()}`;
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

export function createCertificateRenewalIds(idFactory = randomUUID) {
  if (typeof idFactory !== "function") throw new TypeError("An ID factory is required.");
  return Object.freeze({
    certificateId: opaqueId("crt", CERTIFICATE_ID, idFactory),
    renewedEventId: opaqueId("evt", EVENT_ID, idFactory),
    supersededEventId: opaqueId("evt", EVENT_ID, idFactory),
    correlationId: opaqueId("cor", CORRELATION_ID, idFactory),
  });
}

function validateVerifiedCertificate(certificate, request) {
  if (!SUBJECT_ID.test(certificate.subjectId ?? "")
    || !ISSUER_ID.test(certificate.issuerId ?? "")
    || !SERIAL.test(certificate.serialNumber ?? "")
    || !SHA256.test(certificate.fingerprintSha256 ?? "")
    || !SHA256.test(certificate.publicKeySha256 ?? "")
    || !ALGORITHMS.has(request.proofOfPossession?.publicKeyAlgorithm)) {
    deny("VERIFIED_CERTIFICATE_INVALID");
  }
  const requestedAt = requireUtc(request.requestedAt, "ISSUANCE_TIME_INVALID");
  const notBefore = requireUtc(certificate.notBefore, "CERTIFICATE_VALIDITY_INVALID");
  const notAfter = requireUtc(certificate.notAfter, "CERTIFICATE_VALIDITY_INVALID");
  if (notBefore > requestedAt || requestedAt >= notAfter) deny("CERTIFICATE_VALIDITY_INVALID");
}

function certificateRecord({ trustedContext, request, certificate, identifiers, supersedesCertificateId, eventId }) {
  return {
    schemaVersion: "1.0.0",
    tenantId: trustedContext.tenantId,
    certificateId: identifiers.certificateId,
    subjectId: certificate.subjectId,
    issuerId: certificate.issuerId,
    profileId: certificate.profileId,
    serialNumber: certificate.serialNumber,
    fingerprintSha256: certificate.fingerprintSha256,
    publicKeySha256: certificate.publicKeySha256,
    publicKeyAlgorithm: request.proofOfPossession.publicKeyAlgorithm,
    state: "active",
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    issuedAt: request.requestedAt,
    requestedBySubjectId: trustedContext.subjectId,
    requestId: request.requestId,
    idempotencyKey: request.idempotencyKey,
    issuedEventId: eventId,
    lastEventId: eventId,
    correlationId: identifiers.correlationId,
    supersedesCertificateId,
  };
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
    || !CORRELATION_ID.test(identifiers.correlationId ?? "")) deny("INVENTORY_IDS_INVALID");
  if (request.operation !== "issue"
    || request.profileId !== PROFILE_ID
    || !REQUEST_ID.test(request.requestId ?? "")
    || !IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "")
    || request.tenantId !== trustedContext.tenantId
    || request.requestedBySubjectId !== trustedContext.subjectId
    || request.subjectId !== certificate.subjectId
    || request.tenantId !== certificate.tenantId
    || request.profileId !== certificate.profileId) deny("ISSUANCE_BINDING_MISMATCH");

  validateVerifiedCertificate(certificate, request);
  return Object.freeze(certificateRecord({
    trustedContext,
    request,
    certificate,
    identifiers,
    supersedesCertificateId: null,
    eventId: identifiers.eventId,
  }));
}

export function buildRenewedCertificateRecord({
  context,
  normalizedRequest,
  predecessor,
  verifiedCertificate,
  ids = createCertificateRenewalIds(),
} = {}) {
  const trustedContext = requireContext(context);
  const request = requireRecord(normalizedRequest, "RENEWAL_REQUEST_INVALID");
  const previous = requireRecord(predecessor, "RENEWAL_CERTIFICATE_INVALID");
  const certificate = requireRecord(verifiedCertificate, "VERIFIED_CERTIFICATE_INVALID");
  const identifiers = requireRecord(ids, "INVENTORY_IDS_INVALID");

  if (!CERTIFICATE_ID.test(identifiers.certificateId ?? "")
    || !EVENT_ID.test(identifiers.renewedEventId ?? "")
    || !EVENT_ID.test(identifiers.supersededEventId ?? "")
    || identifiers.renewedEventId === identifiers.supersededEventId
    || !CORRELATION_ID.test(identifiers.correlationId ?? "")) deny("INVENTORY_IDS_INVALID");
  if (request.operation !== "renew"
    || request.profileId !== PROFILE_ID
    || !REQUEST_ID.test(request.requestId ?? "")
    || !IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "")
    || request.tenantId !== trustedContext.tenantId
    || request.requestedBySubjectId !== trustedContext.subjectId
    || request.subjectId !== certificate.subjectId
    || request.tenantId !== certificate.tenantId
    || request.profileId !== certificate.profileId
    || request.renewalOfCertificateId !== previous.certificateId
    || previous.tenantId !== trustedContext.tenantId
    || previous.subjectId !== request.subjectId
    || previous.profileId !== PROFILE_ID
    || previous.state !== "active"
    || !SHA256.test(previous.publicKeySha256 ?? "")
    || previous.publicKeySha256 === certificate.publicKeySha256) deny("RENEWAL_BINDING_MISMATCH");

  validateVerifiedCertificate(certificate, request);
  const record = certificateRecord({
    trustedContext,
    request,
    certificate,
    identifiers,
    supersedesCertificateId: previous.certificateId,
    eventId: identifiers.renewedEventId,
  });
  return Object.freeze({
    ...record,
    renewedEventId: identifiers.renewedEventId,
    supersededEventId: identifiers.supersededEventId,
    predecessorLastEventId: previous.lastEventId,
  });
}

export function createCertificateInventoryService({
  insertIssuedCertificate,
  insertRenewedCertificate,
  idFactory = randomUUID,
} = {}) {
  if (typeof insertIssuedCertificate !== "function") throw new TypeError("A certificate inventory repository is required.");

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
        || persisted.state !== "active") deny("INVENTORY_WRITE_UNCONFIRMED");
      return Object.freeze({
        ...verifiedCertificate,
        ...record,
        certificateId: persisted.certificateId,
        issuedEventId: persisted.eventId,
        lastEventId: persisted.eventId,
      });
    },

    async recordRenewedCertificate({ context, normalizedRequest, predecessor, verifiedCertificate } = {}) {
      if (typeof insertRenewedCertificate !== "function") throw new TypeError("A certificate renewal repository is required.");
      const record = buildRenewedCertificateRecord({
        context,
        normalizedRequest,
        predecessor,
        verifiedCertificate,
        ids: createCertificateRenewalIds(idFactory),
      });
      const persisted = await insertRenewedCertificate(record);
      if (!persisted
        || !CERTIFICATE_ID.test(persisted.certificateId ?? "")
        || !EVENT_ID.test(persisted.renewedEventId ?? "")
        || !EVENT_ID.test(persisted.supersededEventId ?? "")
        || persisted.state !== "active"
        || persisted.predecessorState !== "superseded") deny("INVENTORY_WRITE_UNCONFIRMED");
      return Object.freeze({
        ...verifiedCertificate,
        ...record,
        certificateId: persisted.certificateId,
        issuedEventId: persisted.renewedEventId,
        renewedEventId: persisted.renewedEventId,
        lastEventId: persisted.renewedEventId,
        supersededEventId: persisted.supersededEventId,
      });
    },
  });
}
