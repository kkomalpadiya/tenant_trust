import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CERTIFICATE_NOT_ACCEPTED,
  CERTIFICATE_STATUS_POLICY,
  CERTIFICATE_STATUS_UNAVAILABLE,
  CertificateStatusError,
  certificateStatusSafeResponse,
  createCertificateStatusValidationService,
  createPostgresCertificateStatusRepository,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  foreignTenant: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
};
const checkedAt = "2026-09-14T10:00:00.000Z";

function context() {
  return resolveTenantContext({
    authentication: { source: "mtls-certificate", authenticationId: "status-test", tenantId: ids.tenant, subjectId: ids.subject },
    authority: {
      tenant: { tenantId: ids.tenant, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: { tenantId: ids.tenant, subjectId: ids.subject, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

function certificate(overrides = {}) {
  return {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    certificateId: ids.certificate,
    issuerId: ids.issuer,
    serialNumber: "00000000000000000000000000000001",
    fingerprintSha256: "a".repeat(64),
    notBefore: "2026-09-14T09:00:00.000Z",
    notAfter: "2026-09-14T11:00:00.000Z",
    ...overrides,
  };
}

function record(overrides = {}) {
  return {
    ...certificate(),
    state: "active",
    version: 3,
    statusObservedAt: "2026-09-14T09:59:58.000Z",
    ...overrides,
  };
}

function service(loadCertificateStatus, time = checkedAt) {
  return createCertificateStatusValidationService({
    loadCertificateStatus,
    clock: () => new Date(time),
  });
}

test("the policy selects authoritative application status and denies stale or unavailable data", () => {
  assert.deepEqual(CERTIFICATE_STATUS_POLICY, {
    schemaVersion: "1.0.0",
    mechanism: "application-status-v1",
    authoritativeSource: "postgresql-certificate-inventory",
    maximumSourceAgeSeconds: 5,
    futureClockSkewSeconds: 2,
    acceptedResultLifetimeSeconds: 30,
    repositoryTimeoutMilliseconds: 1000,
    unknownBehavior: "deny",
    staleBehavior: "deny",
    outageBehavior: "deny",
    cachedAllowOnOutage: false,
  });
});

test("a fresh active inventory match is accepted only until the status or certificate deadline", async () => {
  const validator = service(async () => record());
  const result = await validator.validate({ context: context(), certificate: certificate() });
  assert.equal(result.outcome, "accept");
  assert.equal(result.reasonCode, "CERTIFICATE_ACTIVE");
  assert.equal(result.sourceStatus, "authoritative");
  assert.equal(result.cacheableUntil, "2026-09-14T10:00:28.000Z");
  assert.equal(Object.isFrozen(result), true);

  const nearExpiry = await service(
    async () => record({ notAfter: "2026-09-14T10:00:10.000Z" }),
  ).validate({ context: context(), certificate: certificate({ notAfter: "2026-09-14T10:00:10.000Z" }) });
  assert.equal(nearExpiry.cacheableUntil, "2026-09-14T10:00:10.000Z");
});

test("X.509 not-before and expiry are denied without consulting status storage", async () => {
  let queried = false;
  const validator = service(async () => { queried = true; return record(); });
  const future = await validator.validate({
    context: context(), certificate: certificate({ notBefore: "2026-09-14T10:00:01.000Z" }),
  });
  assert.equal(future.reasonCode, "CERTIFICATE_NOT_YET_VALID");
  const expired = await validator.validate({
    context: context(), certificate: certificate({ notAfter: checkedAt }),
  });
  assert.equal(expired.reasonCode, "CERTIFICATE_EXPIRED");
  assert.equal(queried, false);
});

test("revoked, expired and superseded inventory states deny and are never cacheable", async () => {
  for (const [state, reasonCode] of [
    ["revoked", "CERTIFICATE_REVOKED"],
    ["expired", "CERTIFICATE_EXPIRED"],
    ["superseded", "CERTIFICATE_SUPERSEDED"],
  ]) {
    const result = await service(async () => record({ state })).validate({ context: context(), certificate: certificate() });
    assert.equal(result.outcome, "deny");
    assert.equal(result.reasonCode, reasonCode);
    assert.equal(result.cacheableUntil, null);
  }
});

test("unknown, stale, future-dated and mismatched inventory responses fail closed", async () => {
  const cases = [
    [null, "CERTIFICATE_UNKNOWN", "unknown"],
    [record({ statusObservedAt: "2026-09-14T09:59:54.999Z" }), "STATUS_SOURCE_STALE", "stale"],
    [record({ statusObservedAt: "2026-09-14T10:00:02.001Z" }), "STATUS_SOURCE_STALE", "stale"],
    [record({ tenantId: ids.foreignTenant }), "STATUS_SOURCE_INVALID", "invalid"],
    [record({ fingerprintSha256: "b".repeat(64) }), "STATUS_SOURCE_INVALID", "invalid"],
    [record({ statusObservedAt: null }), "STATUS_SOURCE_INVALID", "invalid"],
  ];
  for (const [status, reasonCode, sourceStatus] of cases) {
    const result = await service(async () => status).validate({ context: context(), certificate: certificate() });
    assert.equal(result.outcome, "deny");
    assert.equal(result.reasonCode, reasonCode);
    assert.equal(result.sourceStatus, sourceStatus);
    assert.equal(result.cacheableUntil, null);
  }
});

test("repository failure and timeout return non-cacheable outage denials without stale fallback", async () => {
  const failure = await service(async () => { throw new Error("database offline"); })
    .validate({ context: context(), certificate: certificate() });
  assert.equal(failure.reasonCode, "STATUS_SOURCE_UNAVAILABLE");
  assert.equal(failure.cacheableUntil, null);

  const timeout = await service(async () => new Promise(() => {}))
    .validate({ context: context(), certificate: certificate() });
  assert.equal(timeout.reasonCode, "STATUS_SOURCE_TIMEOUT");
  assert.equal(timeout.sourceStatus, "unavailable");
  assert.equal(timeout.cacheableUntil, null);
});

test("safe external responses distinguish rejection from infrastructure unavailability", async () => {
  const revoked = await service(async () => record({ state: "revoked" }))
    .validate({ context: context(), certificate: certificate() });
  const outage = await service(async () => { throw new Error("offline"); })
    .validate({ context: context(), certificate: certificate() });
  assert.deepEqual(certificateStatusSafeResponse(revoked), CERTIFICATE_NOT_ACCEPTED);
  assert.deepEqual(certificateStatusSafeResponse(outage), CERTIFICATE_STATUS_UNAVAILABLE);
});

test("a presented certificate cannot select another tenant or subject", async () => {
  for (const presented of [certificate({ tenantId: ids.foreignTenant }), certificate({ subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac" })]) {
    await assert.rejects(
      service(async () => record()).validate({ context: context(), certificate: presented }),
      (error) => error instanceof CertificateStatusError && error.reasonCode === "PRESENTED_CERTIFICATE_INVALID",
    );
  }
});

test("the PostgreSQL adapter uses bound parameters and normalizes database timestamps", async () => {
  let invocation;
  const repository = createPostgresCertificateStatusRepository({
    query: async (sql, values, options) => {
      invocation = { sql, values, options };
      return { rows: [{
        tenant_id: ids.tenant,
        certificate_id: ids.certificate,
        subject_id: ids.subject,
        issuer_id: ids.issuer,
        serial_number: certificate().serialNumber,
        fingerprint_sha256: certificate().fingerprintSha256,
        state: "active",
        not_before: new Date(certificate().notBefore),
        not_after: new Date(certificate().notAfter),
        version: "3",
        status_observed_at: new Date("2026-09-14T09:59:58.000Z"),
      }] };
    },
  });
  const signal = new AbortController().signal;
  const status = await repository({
    tenantId: ids.tenant,
    certificateId: ids.certificate,
    issuerId: ids.issuer,
    serialNumber: certificate().serialNumber,
    fingerprintSha256: certificate().fingerprintSha256,
  }, { signal });
  assert.match(invocation.sql, /tenant_id = \$1/u);
  assert.deepEqual(invocation.values, [ids.tenant, ids.certificate, ids.issuer, certificate().serialNumber, certificate().fingerprintSha256]);
  assert.equal(invocation.options.signal, signal);
  assert.equal(status.version, 3);
  assert.equal(status.statusObservedAt, "2026-09-14T09:59:58.000Z");
});
