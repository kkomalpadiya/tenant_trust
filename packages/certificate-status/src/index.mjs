import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ISSUER_ID = /^iss_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SERIAL = /^(?!0{32}$)[0-9A-F]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const STATES = new Set(["active", "revoked", "expired", "superseded"]);

export const CERTIFICATE_STATUS_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  mechanism: "application-status-v1",
  authoritativeSource: "postgresql-certificate-inventory",
  maximumSourceAgeSeconds: 5,
  futureClockSkewSeconds: 2,
  acceptedResultLifetimeSeconds: 30,
  repositoryTimeoutMilliseconds: 1_000,
  unknownBehavior: "deny",
  staleBehavior: "deny",
  outageBehavior: "deny",
  cachedAllowOnOutage: false,
});

export const CERTIFICATE_NOT_ACCEPTED = Object.freeze({
  statusCode: 401,
  code: "CERTIFICATE_NOT_ACCEPTED",
});

export const CERTIFICATE_STATUS_UNAVAILABLE = Object.freeze({
  statusCode: 503,
  code: "CERTIFICATE_STATUS_UNAVAILABLE",
});

export class CertificateStatusError extends Error {
  constructor(reasonCode) {
    super("Certificate status validation failed.");
    this.name = "CertificateStatusError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new CertificateStatusError(reasonCode);
}

function trustedContext(context) {
  try {
    return assertNoTenantSwitch(context, []);
  } catch (error) {
    if (error instanceof TenantContextError) fail("TENANT_CONTEXT_INVALID");
    throw error;
  }
}

function dateFrom(value, reasonCode) {
  if (!(value instanceof Date) && typeof value !== "string") fail(reasonCode);
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())
    || (typeof value === "string" && date.toISOString() !== value)) fail(reasonCode);
  return date;
}

function validatePresentedCertificate(context, certificate) {
  if (!certificate || typeof certificate !== "object" || Array.isArray(certificate)
    || !CERTIFICATE_ID.test(certificate.certificateId ?? "")
    || !SUBJECT_ID.test(certificate.subjectId ?? "")
    || !ISSUER_ID.test(certificate.issuerId ?? "")
    || !SERIAL.test(certificate.serialNumber ?? "")
    || !SHA256.test(certificate.fingerprintSha256 ?? "")
    || certificate.tenantId !== context.tenantId
    || certificate.subjectId !== context.subjectId) {
    fail("PRESENTED_CERTIFICATE_INVALID");
  }
  const notBefore = dateFrom(certificate.notBefore, "PRESENTED_CERTIFICATE_INVALID");
  const notAfter = dateFrom(certificate.notAfter, "PRESENTED_CERTIFICATE_INVALID");
  if (notBefore >= notAfter) fail("PRESENTED_CERTIFICATE_INVALID");
  return { certificate, notBefore, notAfter };
}

function verdict({
  context,
  certificate,
  checkedAt,
  outcome,
  reasonCode,
  inventoryState = "unknown",
  sourceStatus,
  statusVersion = null,
  statusObservedAt = null,
  cacheableUntil = null,
}) {
  return Object.freeze({
    schemaVersion: CERTIFICATE_STATUS_POLICY.schemaVersion,
    mechanism: CERTIFICATE_STATUS_POLICY.mechanism,
    outcome,
    reasonCode,
    tenantId: context.tenantId,
    subjectId: certificate.subjectId,
    certificateId: certificate.certificateId,
    issuerId: certificate.issuerId,
    serialNumber: certificate.serialNumber,
    fingerprintSha256: certificate.fingerprintSha256,
    inventoryState,
    sourceStatus,
    statusVersion,
    statusObservedAt,
    checkedAt: checkedAt.toISOString(),
    cacheableUntil,
  });
}

function deny(parameters) {
  return verdict({ ...parameters, outcome: "deny", cacheableUntil: null });
}

async function loadWithTimeout(loadCertificateStatus, query, timeoutMilliseconds) {
  const controller = new AbortController();
  let timeout;
  const timedOut = new Promise((resolve) => {
    timeout = setTimeout(() => {
      controller.abort();
      resolve({ kind: "timeout" });
    }, timeoutMilliseconds);
  });
  try {
    const loaded = Promise.resolve()
      .then(() => loadCertificateStatus(query, { signal: controller.signal }))
      .then((record) => ({ kind: "record", record }))
      .catch(() => ({ kind: "error" }));
    return await Promise.race([loaded, timedOut]);
  } finally {
    clearTimeout(timeout);
  }
}

export function createCertificateStatusValidationService({
  loadCertificateStatus,
  clock = () => new Date(),
  policy = CERTIFICATE_STATUS_POLICY,
} = {}) {
  if (typeof loadCertificateStatus !== "function") throw new TypeError("A certificate status repository is required.");
  if (policy !== CERTIFICATE_STATUS_POLICY) throw new TypeError("The versioned certificate status policy is immutable.");

  return Object.freeze({
    async validate({ context, certificate } = {}) {
      const resolvedContext = trustedContext(context);
      const presented = validatePresentedCertificate(resolvedContext, certificate);
      const checkedAt = dateFrom(clock(), "STATUS_CHECK_TIME_INVALID");
      const base = { context: resolvedContext, certificate, checkedAt };

      if (checkedAt < presented.notBefore) {
        return deny({ ...base, reasonCode: "CERTIFICATE_NOT_YET_VALID", sourceStatus: "not-queried" });
      }
      if (checkedAt >= presented.notAfter) {
        return deny({ ...base, reasonCode: "CERTIFICATE_EXPIRED", inventoryState: "expired", sourceStatus: "not-queried" });
      }

      const query = Object.freeze({
        tenantId: resolvedContext.tenantId,
        certificateId: certificate.certificateId,
        issuerId: certificate.issuerId,
        serialNumber: certificate.serialNumber,
        fingerprintSha256: certificate.fingerprintSha256,
      });
      const loaded = await loadWithTimeout(loadCertificateStatus, query, policy.repositoryTimeoutMilliseconds);
      if (loaded.kind === "timeout") {
        return deny({ ...base, reasonCode: "STATUS_SOURCE_TIMEOUT", sourceStatus: "unavailable" });
      }
      if (loaded.kind === "error") {
        return deny({ ...base, reasonCode: "STATUS_SOURCE_UNAVAILABLE", sourceStatus: "unavailable" });
      }
      if (!loaded.record) {
        return deny({ ...base, reasonCode: "CERTIFICATE_UNKNOWN", sourceStatus: "unknown" });
      }

      const record = loaded.record;
      if (!STATES.has(record.state)
        || !Number.isSafeInteger(record.version)
        || record.version < 1
        || record.tenantId !== resolvedContext.tenantId
        || record.certificateId !== certificate.certificateId
        || record.subjectId !== certificate.subjectId
        || record.issuerId !== certificate.issuerId
        || record.serialNumber !== certificate.serialNumber
        || record.fingerprintSha256 !== certificate.fingerprintSha256
        || record.notBefore !== certificate.notBefore
        || record.notAfter !== certificate.notAfter) {
        return deny({ ...base, reasonCode: "STATUS_SOURCE_INVALID", sourceStatus: "invalid" });
      }

      let observedAt;
      try {
        observedAt = dateFrom(record.statusObservedAt, "STATUS_SOURCE_INVALID");
      } catch (error) {
        if (!(error instanceof CertificateStatusError)) throw error;
        return deny({ ...base, reasonCode: "STATUS_SOURCE_INVALID", inventoryState: record.state, sourceStatus: "invalid" });
      }
      const sourceAgeMilliseconds = checkedAt.getTime() - observedAt.getTime();
      if (sourceAgeMilliseconds > policy.maximumSourceAgeSeconds * 1_000
        || sourceAgeMilliseconds < -policy.futureClockSkewSeconds * 1_000) {
        return deny({
          ...base,
          reasonCode: "STATUS_SOURCE_STALE",
          inventoryState: record.state,
          sourceStatus: "stale",
          statusVersion: record.version,
          statusObservedAt: observedAt.toISOString(),
        });
      }

      const authoritative = {
        ...base,
        inventoryState: record.state,
        sourceStatus: "authoritative",
        statusVersion: record.version,
        statusObservedAt: observedAt.toISOString(),
      };
      if (record.state === "revoked") return deny({ ...authoritative, reasonCode: "CERTIFICATE_REVOKED" });
      if (record.state === "expired") return deny({ ...authoritative, reasonCode: "CERTIFICATE_EXPIRED" });
      if (record.state === "superseded") return deny({ ...authoritative, reasonCode: "CERTIFICATE_SUPERSEDED" });

      const cacheDeadline = Math.min(
        observedAt.getTime() + policy.acceptedResultLifetimeSeconds * 1_000,
        presented.notAfter.getTime(),
      );
      if (cacheDeadline <= checkedAt.getTime()) {
        return deny({ ...authoritative, reasonCode: "STATUS_SOURCE_STALE", sourceStatus: "stale" });
      }
      return verdict({
        ...authoritative,
        outcome: "accept",
        reasonCode: "CERTIFICATE_ACTIVE",
        cacheableUntil: new Date(cacheDeadline).toISOString(),
      });
    },
  });
}

export function certificateStatusSafeResponse(result) {
  if (!result || result.outcome !== "deny") fail("STATUS_RESULT_INVALID");
  if (["STATUS_SOURCE_TIMEOUT", "STATUS_SOURCE_UNAVAILABLE", "STATUS_SOURCE_INVALID", "STATUS_SOURCE_STALE"].includes(result.reasonCode)) {
    return CERTIFICATE_STATUS_UNAVAILABLE;
  }
  return CERTIFICATE_NOT_ACCEPTED;
}

const STATUS_QUERY = `
SELECT tenant_id, certificate_id, subject_id, issuer_id, serial_number,
       fingerprint_sha256, state, not_before, not_after, version,
       transaction_timestamp() AS status_observed_at
FROM identity.certificates
WHERE tenant_id = $1
  AND certificate_id = $2
  AND issuer_id = $3
  AND serial_number = $4
  AND fingerprint_sha256 = $5
LIMIT 1`;

export function createPostgresCertificateStatusRepository({ query } = {}) {
  if (typeof query !== "function") throw new TypeError("A transaction-bound PostgreSQL query function is required.");
  return async function loadCertificateStatus(criteria, { signal } = {}) {
    const result = await query(STATUS_QUERY, [
      criteria.tenantId,
      criteria.certificateId,
      criteria.issuerId,
      criteria.serialNumber,
      criteria.fingerprintSha256,
    ], { signal });
    if (!result || !Array.isArray(result.rows) || result.rows.length > 1) fail("STATUS_SOURCE_INVALID");
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
      notBefore: dateFrom(row.not_before, "STATUS_SOURCE_INVALID").toISOString(),
      notAfter: dateFrom(row.not_after, "STATUS_SOURCE_INVALID").toISOString(),
      version: Number(row.version),
      statusObservedAt: dateFrom(row.status_observed_at, "STATUS_SOURCE_INVALID").toISOString(),
    };
  };
}
