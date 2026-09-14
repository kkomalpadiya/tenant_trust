import { createHash, X509Certificate } from "node:crypto";
import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDEMPOTENCY_KEY = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CSR_PEM = /^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\r?\n?$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const PROFILE_ID = "tenant-client-auth-v1";
const ALGORITHMS = new Set(["ecdsa-p256", "ed25519"]);
const CLIENT_AUTH_OIDS = new Set(["1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication", "clientAuth"]);
const ISSUE_REQUEST_FIELDS = ["idempotencyKey", "profileId", "proofOfPossession", "requestId", "requestedValiditySeconds", "subjectId"];
const RENEW_REQUEST_FIELDS = [...ISSUE_REQUEST_FIELDS, "renewalOfCertificateId"];
const PROOF_FIELDS = ["csrPem", "csrSha256", "publicKeyAlgorithm"];

export const CERTIFICATE_ISSUANCE_DENIAL = Object.freeze({
  statusCode: 403,
  code: "CERTIFICATE_ENROLLMENT_DENIED",
});

export class CertificateIssuanceError extends Error {
  constructor(reasonCode) {
    super("Certificate enrollment denied.");
    this.name = "CertificateIssuanceError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new CertificateIssuanceError(reasonCode);
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

function requireResolvedContext(context) {
  try {
    return assertNoTenantSwitch(context, []);
  } catch (error) {
    if (error instanceof TenantContextError) deny("TENANT_CONTEXT_INVALID");
    throw error;
  }
}

function normalizeDate(clock) {
  const value = clock();
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) deny("ISSUANCE_TIME_INVALID");
  return date;
}

function normalizeCertificateRequest({ context, request, operation, clock }) {
  const trustedContext = requireResolvedContext(context);
  const fields = operation === "renew" ? RENEW_REQUEST_FIELDS : ISSUE_REQUEST_FIELDS;
  const input = requireExactFields(request, fields, "REQUEST_FIELDS_INVALID");
  const proof = requireExactFields(input.proofOfPossession, PROOF_FIELDS, "PROOF_OF_POSSESSION_INVALID");

  if (!REQUEST_ID.test(input.requestId ?? "")) deny("REQUEST_ID_INVALID");
  if (input.profileId !== PROFILE_ID) deny("CERTIFICATE_PROFILE_UNSUPPORTED");
  if (!SUBJECT_ID.test(input.subjectId ?? "")) deny("TARGET_SUBJECT_INVALID");
  if (operation === "renew" && !CERTIFICATE_ID.test(input.renewalOfCertificateId ?? "")) deny("RENEWAL_CERTIFICATE_INVALID");
  if (!Number.isSafeInteger(input.requestedValiditySeconds)
    || input.requestedValiditySeconds < 300
    || input.requestedValiditySeconds > 86_400) {
    deny("REQUESTED_VALIDITY_INVALID");
  }
  if (!IDEMPOTENCY_KEY.test(input.idempotencyKey ?? "")) deny("IDEMPOTENCY_KEY_INVALID");
  if (!ALGORITHMS.has(proof.publicKeyAlgorithm)) deny("PUBLIC_KEY_ALGORITHM_UNSUPPORTED");
  if (typeof proof.csrPem !== "string"
    || proof.csrPem.length < 80
    || proof.csrPem.length > 8192
    || !CSR_PEM.test(proof.csrPem)) {
    deny("CSR_INVALID");
  }
  if (!SHA256.test(proof.csrSha256 ?? "")) deny("CSR_DIGEST_INVALID");
  const calculatedDigest = createHash("sha256").update(proof.csrPem, "utf8").digest("hex");
  if (calculatedDigest !== proof.csrSha256) deny("CSR_DIGEST_MISMATCH");

  const requestedAt = normalizeDate(clock);
  return Object.freeze({
    schemaVersion: "1.0.0",
    requestId: input.requestId,
    profileId: PROFILE_ID,
    operation,
    tenantId: trustedContext.tenantId,
    subjectId: input.subjectId,
    requestedBySubjectId: trustedContext.subjectId,
    requestedAt: requestedAt.toISOString(),
    requestedValiditySeconds: input.requestedValiditySeconds,
    proofOfPossession: Object.freeze({ ...proof }),
    renewalOfCertificateId: operation === "renew" ? input.renewalOfCertificateId : null,
    idempotencyKey: input.idempotencyKey,
  });
}

export function normalizeCertificateIssueRequest({ context, request, clock = () => new Date() } = {}) {
  return normalizeCertificateRequest({ context, request, operation: "issue", clock });
}

export function normalizeCertificateRenewalRequest({ context, request, clock = () => new Date() } = {}) {
  return normalizeCertificateRequest({ context, request, operation: "renew", clock });
}

async function authorizeTarget({ trustedContext, normalizedRequest, loadTargetMembership }) {
  if (typeof loadTargetMembership !== "function") throw new TypeError("A target membership repository is required.");
  const target = await loadTargetMembership({
    tenantId: trustedContext.tenantId,
    subjectId: normalizedRequest.subjectId,
  });
  if (!target
    || target.tenantId !== trustedContext.tenantId
    || target.subjectId !== normalizedRequest.subjectId
    || target.tenantState !== "active"
    || target.subjectState !== "active"
    || target.membershipState !== "active") {
    deny("TARGET_MEMBERSHIP_INACTIVE");
  }
  if (normalizedRequest.subjectId !== trustedContext.subjectId
    && !trustedContext.roles.includes("tenant-admin")) {
    deny("SUBJECT_ENROLLMENT_UNAUTHORIZED");
  }
}

async function requireIssuer({ tenantId, operation, resolveIssuer }) {
  if (typeof resolveIssuer !== "function") throw new TypeError("An issuer repository is required.");
  const issuer = await resolveIssuer({ tenantId });
  if (!issuer) deny("ACTIVE_ISSUER_REQUIRED");
  if (issuer.tenantId !== tenantId) deny("ISSUER_TENANT_MISMATCH");
  if (!ISSUER_ID.test(issuer.issuerId ?? "")
    || issuer.state !== "active"
    || !Array.isArray(issuer.allowedCertificateOperations)
    || !issuer.allowedCertificateOperations.includes(operation)
    || typeof issuer.issuerName !== "string"
    || issuer.issuerName.length < 1
    || typeof issuer.authorityUrl !== "string"
    || !/^https:\/\/[^\s]+$/u.test(issuer.authorityUrl)
    || typeof issuer.issuerCertificatePem !== "string"
    || issuer.issuerCertificatePem.length < 80) {
    deny("ACTIVE_ISSUER_REQUIRED");
  }
  return issuer;
}

function freezeSigningInstruction(instruction) {
  Object.freeze(instruction.subject);
  Object.freeze(instruction.subjectAlternativeNames);
  Object.freeze(instruction.extensions.keyUsage);
  Object.freeze(instruction.extensions.extendedKeyUsage);
  Object.freeze(instruction.extensions);
  return Object.freeze(instruction);
}

function buildSigningInstruction({ normalizedRequest, issuer, publicKeySha256 = null, rotatesFromPublicKeySha256 = null }) {
  const issuedAt = new Date(normalizedRequest.requestedAt);
  const notBefore = new Date(issuedAt.getTime() - 60_000);
  const notAfter = new Date(notBefore.getTime() + normalizedRequest.requestedValiditySeconds * 1000);
  const identityUri = `urn:tenant-trust:identity:v1:tenant:${normalizedRequest.tenantId}:subject:${normalizedRequest.subjectId}`;
  return freezeSigningInstruction({
    operation: normalizedRequest.operation,
    tenantId: normalizedRequest.tenantId,
    subjectId: normalizedRequest.subjectId,
    issuerId: issuer.issuerId,
    issuerName: issuer.issuerName,
    authorityUrl: issuer.authorityUrl,
    profileId: PROFILE_ID,
    renewalOfCertificateId: normalizedRequest.renewalOfCertificateId,
    csrPem: normalizedRequest.proofOfPossession.csrPem,
    csrSha256: normalizedRequest.proofOfPossession.csrSha256,
    publicKeyAlgorithm: normalizedRequest.proofOfPossession.publicKeyAlgorithm,
    publicKeySha256,
    rotatesFromPublicKeySha256,
    subject: { commonName: normalizedRequest.subjectId, organizationName: normalizedRequest.tenantId },
    subjectAlternativeNames: [identityUri],
    extensions: {
      basicConstraintsCa: false,
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["clientAuth"],
    },
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  });
}

export async function prepareCertificateIssuance({ context, request, loadTargetMembership, resolveIssuer, clock = () => new Date() } = {}) {
  const trustedContext = requireResolvedContext(context);
  const normalizedRequest = normalizeCertificateIssueRequest({ context: trustedContext, request, clock });
  await authorizeTarget({ trustedContext, normalizedRequest, loadTargetMembership });
  const issuer = await requireIssuer({ tenantId: trustedContext.tenantId, operation: "issue", resolveIssuer });
  const signingInstruction = buildSigningInstruction({ normalizedRequest, issuer });
  return Object.freeze({ normalizedRequest, issuer, signingInstruction });
}

export async function prepareCertificateRenewal({
  context,
  request,
  loadTargetMembership,
  loadRenewalCertificate,
  inspectCertificateRequest,
  resolveIssuer,
  clock = () => new Date(),
} = {}) {
  if (typeof loadRenewalCertificate !== "function" || typeof inspectCertificateRequest !== "function") {
    throw new TypeError("Certificate renewal repositories and CSR inspection are required.");
  }
  const trustedContext = requireResolvedContext(context);
  const normalizedRequest = normalizeCertificateRenewalRequest({ context: trustedContext, request, clock });
  await authorizeTarget({ trustedContext, normalizedRequest, loadTargetMembership });

  const predecessor = await loadRenewalCertificate({
    tenantId: trustedContext.tenantId,
    certificateId: normalizedRequest.renewalOfCertificateId,
    subjectId: normalizedRequest.subjectId,
  });
  if (!predecessor
    || predecessor.tenantId !== trustedContext.tenantId
    || predecessor.certificateId !== normalizedRequest.renewalOfCertificateId
    || predecessor.subjectId !== normalizedRequest.subjectId
    || predecessor.profileId !== PROFILE_ID
    || predecessor.state !== "active"
    || !SHA256.test(predecessor.publicKeySha256 ?? "")) {
    deny("RENEWAL_CERTIFICATE_INELIGIBLE");
  }

  const notBefore = new Date(predecessor.notBefore);
  const notAfter = new Date(predecessor.notAfter);
  const requestedAt = new Date(normalizedRequest.requestedAt);
  const validityMs = notAfter.getTime() - notBefore.getTime();
  const renewalWindowStart = notAfter.getTime() - validityMs / 4;
  if (!Number.isFinite(validityMs)
    || validityMs <= 0
    || requestedAt < notBefore
    || requestedAt >= notAfter
    || requestedAt.getTime() < renewalWindowStart) {
    deny("RENEWAL_WINDOW_CLOSED");
  }

  const inspected = requireRecord(await inspectCertificateRequest(normalizedRequest.proofOfPossession.csrPem), "CSR_INSPECTION_FAILED");
  if (!SHA256.test(inspected.publicKeySha256 ?? "")
    || inspected.publicKeyAlgorithm !== normalizedRequest.proofOfPossession.publicKeyAlgorithm) {
    deny("CSR_KEY_BINDING_MISMATCH");
  }
  if (inspected.publicKeySha256 === predecessor.publicKeySha256) deny("KEY_ROTATION_REQUIRED");

  const issuer = await requireIssuer({ tenantId: trustedContext.tenantId, operation: "renew", resolveIssuer });
  const signingInstruction = buildSigningInstruction({
    normalizedRequest,
    issuer,
    publicKeySha256: inspected.publicKeySha256,
    rotatesFromPublicKeySha256: predecessor.publicKeySha256,
  });
  return Object.freeze({ normalizedRequest, issuer, predecessor, signingInstruction });
}

function parseDistinguishedName(value) {
  return Object.fromEntries(value.split(/\n|,\s*(?=[A-Z][A-Z0-9.]*=)/u).map((entry) => {
    const separator = entry.indexOf("=");
    return separator < 1 ? [entry, ""] : [entry.slice(0, separator), entry.slice(separator + 1)];
  }));
}

function publicKeyMatches(certificate, algorithm) {
  if (algorithm === "ed25519") return certificate.publicKey.asymmetricKeyType === "ed25519";
  return certificate.publicKey.asymmetricKeyType === "ec"
    && ["prime256v1", "P-256"].includes(certificate.publicKey.asymmetricKeyDetails?.namedCurve);
}

export function verifyIssuedCertificate({ certificatePem, prepared } = {}) {
  if (typeof certificatePem !== "string" || certificatePem.length < 80) deny("CERTIFICATE_INVALID");
  const issuance = requireRecord(prepared, "ISSUANCE_RESULT_INVALID");
  let certificate;
  let issuerCertificate;
  try {
    certificate = new X509Certificate(certificatePem);
    issuerCertificate = new X509Certificate(issuance.issuer.issuerCertificatePem);
  } catch {
    deny("CERTIFICATE_INVALID");
  }

  const expected = issuance.signingInstruction;
  const subject = parseDistinguishedName(certificate.subject);
  const issuerSubject = parseDistinguishedName(issuerCertificate.subject);
  if (Object.keys(subject).sort().join(",") !== "CN,O"
    || subject.CN !== expected.subject.commonName
    || subject.O !== expected.subject.organizationName) {
    deny("CERTIFICATE_IDENTITY_MISMATCH");
  }
  if (certificate.subjectAltName !== `URI:${expected.subjectAlternativeNames[0]}`) deny("CERTIFICATE_SAN_MISMATCH");
  if (certificate.ca || !issuerCertificate.ca
    || issuerSubject.CN !== expected.issuerName
    || !certificate.checkIssued(issuerCertificate)
    || !certificate.verify(issuerCertificate.publicKey)) {
    deny("CERTIFICATE_ISSUER_MISMATCH");
  }
  if (!publicKeyMatches(certificate, expected.publicKeyAlgorithm)) deny("CERTIFICATE_KEY_MISMATCH");
  const publicKeySha256 = createHash("sha256")
    .update(certificate.publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  if (!SHA256.test(publicKeySha256)
    || (expected.publicKeySha256 && expected.publicKeySha256 !== publicKeySha256)) {
    deny("CERTIFICATE_KEY_MISMATCH");
  }
  const usages = certificate.keyUsage ?? [];
  if (usages.length !== 1 || !CLIENT_AUTH_OIDS.has(usages[0])) deny("CERTIFICATE_USAGE_MISMATCH");

  const notBefore = new Date(certificate.validFrom);
  const notAfter = new Date(certificate.validTo);
  const requestedAt = new Date(issuance.normalizedRequest.requestedAt);
  const duration = notAfter.getTime() - notBefore.getTime();
  if (!Number.isFinite(notBefore.getTime())
    || !Number.isFinite(notAfter.getTime())
    || notBefore.getTime() < requestedAt.getTime() - 120_000
    || notBefore.getTime() > requestedAt.getTime() + 10_000
    || notAfter.getTime() <= requestedAt.getTime()
    || duration < 300_000
    || duration > issuance.normalizedRequest.requestedValiditySeconds * 1000 + 1_000) {
    deny("CERTIFICATE_VALIDITY_MISMATCH");
  }

  const serialNumber = certificate.serialNumber.toUpperCase().padStart(32, "0");
  if (!SERIAL.test(serialNumber)) deny("CERTIFICATE_SERIAL_INVALID");
  const fingerprintSha256 = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
  if (!SHA256.test(fingerprintSha256)) deny("CERTIFICATE_FINGERPRINT_INVALID");

  return Object.freeze({
    certificatePem,
    profileId: PROFILE_ID,
    tenantId: expected.tenantId,
    subjectId: expected.subjectId,
    issuerId: expected.issuerId,
    serialNumber,
    fingerprintSha256,
    publicKeySha256,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  });
}

export function createCertificateIssuanceService(dependencies = {}) {
  const {
    loadTargetMembership,
    loadRenewalCertificate,
    inspectCertificateRequest,
    resolveIssuer,
    signCertificate,
    recordIssuedCertificate,
    recordRenewedCertificate,
    clock = () => new Date(),
  } = dependencies;
  if (typeof signCertificate !== "function") throw new TypeError("A certificate signer is required.");
  if (typeof recordIssuedCertificate !== "function") throw new TypeError("A certificate inventory writer is required.");

  return Object.freeze({
    async issue({ context, request } = {}) {
      const prepared = await prepareCertificateIssuance({ context, request, loadTargetMembership, resolveIssuer, clock });
      const result = await signCertificate(prepared.signingInstruction);
      const verifiedCertificate = verifyIssuedCertificate({ certificatePem: result?.certificatePem, prepared });
      return recordIssuedCertificate({ context, normalizedRequest: prepared.normalizedRequest, verifiedCertificate });
    },

    async renew({ context, request } = {}) {
      if (typeof recordRenewedCertificate !== "function") throw new TypeError("A certificate renewal inventory writer is required.");
      const prepared = await prepareCertificateRenewal({
        context,
        request,
        loadTargetMembership,
        loadRenewalCertificate,
        inspectCertificateRequest,
        resolveIssuer,
        clock,
      });
      const result = await signCertificate(prepared.signingInstruction);
      const verifiedCertificate = verifyIssuedCertificate({ certificatePem: result?.certificatePem, prepared });
      return recordRenewedCertificate({
        context,
        normalizedRequest: prepared.normalizedRequest,
        predecessor: prepared.predecessor,
        verifiedCertificate,
      });
    },
  });
}

export function certificateIssuanceSafeDenial(error) {
  if (!(error instanceof CertificateIssuanceError)) throw error;
  return CERTIFICATE_ISSUANCE_DENIAL;
}
