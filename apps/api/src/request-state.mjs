import {
  CERTIFICATE_STATUS_POLICY,
  certificateStatusSafeResponse,
  createCertificateStatusValidationService,
  createPostgresCertificateStatusRepository,
} from "@tenant-trust/certificate-status";

const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const REQUEST_STATES = new WeakSet();

export const REQUEST_STATE_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  mechanism: "authoritative-per-request-state-v1",
  maximumStateAgeSeconds: CERTIFICATE_STATUS_POLICY.maximumSourceAgeSeconds,
  futureClockSkewSeconds: CERTIFICATE_STATUS_POLICY.futureClockSkewSeconds,
  crossRequestAllowCache: false,
  revalidation: "every-protected-request",
});

export class CertificateNotAcceptedError extends Error {
  constructor() {
    super("Certificate not accepted.");
    this.name = "CertificateNotAcceptedError";
  }
}

export class RequestStateUnavailableError extends Error {
  constructor() {
    super("Authoritative request state unavailable.");
    this.name = "RequestStateUnavailableError";
  }
}

function asDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new CertificateNotAcceptedError();
  return date;
}

export function assertPresentedCertificate(authentication) {
  const certificate = authentication?.certificate;
  if (!certificate || typeof certificate !== "object" || Array.isArray(certificate)
    || certificate.profileId !== "tenant-client-auth-v1"
    || !ISSUER_ID.test(certificate.issuerId ?? "")
    || !SERIAL.test(certificate.serialNumber ?? "")
    || !SHA256.test(certificate.fingerprintSha256 ?? "")
    || !SHA256.test(certificate.publicKeySha256 ?? "")
    || authentication.authenticationId !== `sha256:${certificate.fingerprintSha256}`) {
    throw new CertificateNotAcceptedError();
  }
  const notBefore = asDate(certificate.notBefore);
  const notAfter = asDate(certificate.notAfter);
  if (notBefore >= notAfter) throw new CertificateNotAcceptedError();
  return Object.freeze({
    profileId: certificate.profileId,
    issuerId: certificate.issuerId,
    serialNumber: certificate.serialNumber,
    fingerprintSha256: certificate.fingerprintSha256,
    publicKeySha256: certificate.publicKeySha256,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  });
}

function exactDate(clock) {
  let value;
  try {
    value = clock();
  } catch {
    throw new RequestStateUnavailableError();
  }
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new RequestStateUnavailableError();
  }
  return value;
}

function throwStatusDenial(verdict) {
  let safe;
  try {
    safe = certificateStatusSafeResponse(verdict);
  } catch {
    throw new RequestStateUnavailableError();
  }
  if (safe.code === "CERTIFICATE_NOT_ACCEPTED") throw new CertificateNotAcceptedError();
  throw new RequestStateUnavailableError();
}

const PRESENTED_CERTIFICATE_QUERY = `
SELECT certificate_id::text
FROM identity.certificates
WHERE tenant_id = $1::identity.tenant_id
  AND subject_id = $2::identity.subject_id
  AND issuer_id = $3::identity.issuer_id
  AND profile_id = $4::identity.certificate_profile_id
  AND serial_number = $5::identity.x509_serial_number
  AND fingerprint_sha256 = $6::identity.sha256_digest
  AND not_before = $7::timestamptz
  AND not_after = $8::timestamptz
ORDER BY certificate_id
LIMIT 2`;

export function createRequestStateRevalidator({ clock = () => new Date() } = {}) {
  if (typeof clock !== "function") throw new TypeError("A trusted request-state clock is required.");

  function assertFresh(state) {
    if (!state || !REQUEST_STATES.has(state) || state.policy !== REQUEST_STATE_POLICY) {
      throw new RequestStateUnavailableError();
    }
    const now = exactDate(clock);
    const observedAt = asDate(state.observedAt);
    const validUntil = asDate(state.validUntil);
    if (now.getTime() < observedAt.getTime() - REQUEST_STATE_POLICY.futureClockSkewSeconds * 1_000
      || now >= validUntil) {
      throw new RequestStateUnavailableError();
    }
    return state;
  }

  return Object.freeze({
    policy: REQUEST_STATE_POLICY,

    async validate({ client, authentication, context } = {}) {
      if (!client || typeof client.query !== "function") {
        throw new TypeError("A transaction-bound PostgreSQL client is required.");
      }
      const presented = assertPresentedCertificate(authentication);
      let discovery;
      try {
        discovery = await client.query(PRESENTED_CERTIFICATE_QUERY, [
          authentication.tenantId,
          authentication.subjectId,
          presented.issuerId,
          presented.profileId,
          presented.serialNumber,
          presented.fingerprintSha256,
          presented.notBefore,
          presented.notAfter,
        ]);
      } catch {
        throw new RequestStateUnavailableError();
      }
      if (!discovery || !Array.isArray(discovery.rows) || discovery.rows.length > 1) {
        throw new RequestStateUnavailableError();
      }
      if (discovery.rows.length !== 1 || typeof discovery.rows[0].certificate_id !== "string") {
        throw new CertificateNotAcceptedError();
      }

      const certificate = Object.freeze({
        certificateId: discovery.rows[0].certificate_id,
        tenantId: authentication.tenantId,
        subjectId: authentication.subjectId,
        issuerId: presented.issuerId,
        serialNumber: presented.serialNumber,
        fingerprintSha256: presented.fingerprintSha256,
        notBefore: presented.notBefore,
        notAfter: presented.notAfter,
      });
      const loadCertificateStatus = createPostgresCertificateStatusRepository({
        query: (text, values, { signal } = {}) => client.query({ text, values, signal }),
      });
      const validator = createCertificateStatusValidationService({
        loadCertificateStatus,
        clock,
      });
      const verdict = await validator.validate({ context, certificate });
      if (verdict.outcome !== "accept") throwStatusDenial(verdict);

      const observedAt = asDate(verdict.statusObservedAt);
      const cacheableUntil = asDate(verdict.cacheableUntil);
      const validUntil = new Date(Math.min(
        observedAt.getTime() + REQUEST_STATE_POLICY.maximumStateAgeSeconds * 1_000,
        cacheableUntil.getTime(),
      ));
      const state = Object.freeze({
        policy: REQUEST_STATE_POLICY,
        certificateId: certificate.certificateId,
        certificateStatusVersion: verdict.statusVersion,
        authorityVersions: context.versions,
        observedAt: observedAt.toISOString(),
        checkedAt: verdict.checkedAt,
        validUntil: validUntil.toISOString(),
      });
      REQUEST_STATES.add(state);
      assertFresh(state);
      return state;
    },

    assertFresh,
  });
}
