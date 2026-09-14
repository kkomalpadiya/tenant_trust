import { createHash, X509Certificate } from "node:crypto";
import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDEMPOTENCY_KEY = /^[a-z0-9][a-z0-9._:/-]{7,159}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CSR_PEM = /^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\r?\n?$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const PROFILE_ID = "tenant-client-auth-v1";
const ALGORITHMS = new Set(["ecdsa-p256", "ed25519"]);
const CLIENT_AUTH_OIDS = new Set(["1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication", "clientAuth"]);
const REQUEST_FIELDS = ["idempotencyKey", "profileId", "proofOfPossession", "requestId", "requestedValiditySeconds", "subjectId"];
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

function freezeSigningInstruction(instruction) {
  Object.freeze(instruction.subject);
  Object.freeze(instruction.subjectAlternativeNames);
  Object.freeze(instruction.extensions.keyUsage);
  Object.freeze(instruction.extensions.extendedKeyUsage);
  Object.freeze(instruction.extensions);
  return Object.freeze(instruction);
}

export function normalizeCertificateIssueRequest({ context, request, clock = () => new Date() } = {}) {
  const trustedContext = requireResolvedContext(context);
  const input = requireExactFields(request, REQUEST_FIELDS, "REQUEST_FIELDS_INVALID");
  const proof = requireExactFields(input.proofOfPossession, PROOF_FIELDS, "PROOF_OF_POSSESSION_INVALID");

  if (!REQUEST_ID.test(input.requestId ?? "")) deny("REQUEST_ID_INVALID");
  if (input.profileId !== PROFILE_ID) deny("CERTIFICATE_PROFILE_UNSUPPORTED");
  if (!SUBJECT_ID.test(input.subjectId ?? "")) deny("TARGET_SUBJECT_INVALID");
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
    operation: "issue",
    tenantId: trustedContext.tenantId,
    subjectId: input.subjectId,
    requestedBySubjectId: trustedContext.subjectId,
    requestedAt: requestedAt.toISOString(),
    requestedValiditySeconds: input.requestedValiditySeconds,
    proofOfPossession: Object.freeze({ ...proof }),
    renewalOfCertificateId: null,
    idempotencyKey: input.idempotencyKey,
  });
}

export async function prepareCertificateIssuance({
  context,
  request,
  loadTargetMembership,
  resolveIssuer,
  clock = () => new Date(),
} = {}) {
  if (typeof loadTargetMembership !== "function" || typeof resolveIssuer !== "function") {
    throw new TypeError("Certificate issuance repositories are required.");
  }

  const trustedContext = requireResolvedContext(context);
  const normalizedRequest = normalizeCertificateIssueRequest({ context: trustedContext, request, clock });
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

  const issuer = await resolveIssuer({ tenantId: trustedContext.tenantId });
  if (!issuer) deny("ACTIVE_ISSUER_REQUIRED");
  if (issuer.tenantId !== trustedContext.tenantId) deny("ISSUER_TENANT_MISMATCH");
  if (!ISSUER_ID.test(issuer.issuerId ?? "")
    || issuer.state !== "active"
    || !Array.isArray(issuer.allowedCertificateOperations)
    || !issuer.allowedCertificateOperations.includes("issue")
    || typeof issuer.issuerName !== "string"
    || issuer.issuerName.length < 1
    || typeof issuer.authorityUrl !== "string"
    || !/^https:\/\/[^\s]+$/u.test(issuer.authorityUrl)
    || typeof issuer.issuerCertificatePem !== "string"
    || issuer.issuerCertificatePem.length < 80) {
    deny("ACTIVE_ISSUER_REQUIRED");
  }

  const issuedAt = new Date(normalizedRequest.requestedAt);
  const notBefore = new Date(issuedAt.getTime() - 60_000);
  const notAfter = new Date(notBefore.getTime() + normalizedRequest.requestedValiditySeconds * 1000);
  const identityUri = `urn:tenant-trust:identity:v1:tenant:${trustedContext.tenantId}:subject:${normalizedRequest.subjectId}`;
  const signingInstruction = freezeSigningInstruction({
    tenantId: trustedContext.tenantId,
    subjectId: normalizedRequest.subjectId,
    issuerId: issuer.issuerId,
    issuerName: issuer.issuerName,
    authorityUrl: issuer.authorityUrl,
    profileId: PROFILE_ID,
    csrPem: normalizedRequest.proofOfPossession.csrPem,
    csrSha256: normalizedRequest.proofOfPossession.csrSha256,
    publicKeyAlgorithm: normalizedRequest.proofOfPossession.publicKeyAlgorithm,
    subject: { commonName: normalizedRequest.subjectId, organizationName: trustedContext.tenantId },
    subjectAlternativeNames: [identityUri],
    extensions: {
      basicConstraintsCa: false,
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["clientAuth"],
    },
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  });

  return Object.freeze({ normalizedRequest, issuer, signingInstruction });
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
  if (certificate.subjectAltName !== `URI:${expected.subjectAlternativeNames[0]}`) {
    deny("CERTIFICATE_SAN_MISMATCH");
  }
  if (certificate.ca || !issuerCertificate.ca
    || issuerSubject.CN !== expected.issuerName
    || !certificate.checkIssued(issuerCertificate)
    || !certificate.verify(issuerCertificate.publicKey)) {
    deny("CERTIFICATE_ISSUER_MISMATCH");
  }
  if (!publicKeyMatches(certificate, expected.publicKeyAlgorithm)) deny("CERTIFICATE_KEY_MISMATCH");
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
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  });
}

export function createCertificateIssuanceService(dependencies = {}) {
  const { loadTargetMembership, resolveIssuer, signCertificate, clock = () => new Date() } = dependencies;
  if (typeof signCertificate !== "function") throw new TypeError("A certificate signer is required.");

  return Object.freeze({
    async issue({ context, request } = {}) {
      const prepared = await prepareCertificateIssuance({
        context,
        request,
        loadTargetMembership,
        resolveIssuer,
        clock,
      });
      const result = await signCertificate(prepared.signingInstruction);
      return verifyIssuedCertificate({ certificatePem: result?.certificatePem, prepared });
    },
  });
}

export function certificateIssuanceSafeDenial(error) {
  if (!(error instanceof CertificateIssuanceError)) throw error;
  return CERTIFICATE_ISSUANCE_DENIAL;
}
