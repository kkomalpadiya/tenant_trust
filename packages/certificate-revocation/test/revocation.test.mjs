import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CERTIFICATE_REVOCATION_DENIAL,
  CertificateRevocationError,
  REVOCATION_REASON_CODES,
  certificateRevocationSafeDenial,
  createCertificateRevocationIds,
  createCertificateRevocationService,
  createPostgresCertificateRevocationRepository,
  normalizeCertificateRevocationRequest,
  prepareCertificateRevocation,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  foreignTenant: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  bob: "sub_018f1234-5678-7abc-8def-0123456789ac",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  foreignIssuer: "iss_018f1234-5678-7abc-8def-0123456789b5",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789d0",
  lastEvent: "evt_018f1234-5678-7abc-8def-0123456789e0",
  event: "evt_018f1234-5678-7abc-8def-0123456789e1",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789f1",
  request: "req_018f1234-5678-7abc-8def-0123456789c7",
};
const requestedAt = "2026-09-15T09:00:00.000Z";

function context({ subjectId = ids.alice, roles = ["tenant-member"], tenantId = ids.tenant } = {}) {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "revocation-test", tenantId, subjectId },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles,
    },
  });
}

function request(overrides = {}) {
  return {
    requestId: ids.request,
    certificateId: ids.certificate,
    reasonCode: "KEY_COMPROMISE",
    idempotencyKey: "tenant-alpha:certificate:revoke:0001",
    ...overrides,
  };
}

function certificate(overrides = {}) {
  return {
    tenantId: ids.tenant,
    certificateId: ids.certificate,
    subjectId: ids.alice,
    issuerId: ids.issuer,
    serialNumber: "00000000000000000000000000000001",
    fingerprintSha256: "a".repeat(64),
    state: "active",
    lastEventId: ids.lastEvent,
    version: 1,
    ...overrides,
  };
}

function issuer(overrides = {}) {
  return {
    tenantId: ids.tenant,
    issuerId: ids.issuer,
    state: "active",
    authorityUrl: "https://tenant-alpha-ca.local",
    allowedCertificateOperations: ["issue", "renew", "revoke"],
    ...overrides,
  };
}

function confirmation(overrides = {}) {
  return {
    status: "revoked",
    tenantId: ids.tenant,
    certificateId: ids.certificate,
    issuerId: ids.issuer,
    serialNumber: certificate().serialNumber,
    fingerprintSha256: certificate().fingerprintSha256,
    reasonCode: "KEY_COMPROMISE",
    revokedAt: "2026-09-15T09:00:01.000Z",
    issuerConfirmationId: "step-ca:revocation:0001",
    ...overrides,
  };
}

function service(overrides = {}) {
  const generated = [
    "018f1234-5678-7abc-8def-0123456789e1",
    "018f1234-5678-7abc-8def-0123456789f1",
  ];
  return createCertificateRevocationService({
    loadCertificate: async () => certificate(),
    loadExistingRevocation: async () => null,
    resolveIssuer: async () => issuer(),
    revokeAtIssuer: async () => confirmation(),
    recordRevocation: async (record) => ({
      certificateId: record.certificateId,
      eventId: record.eventId,
      correlationId: record.correlationId,
      state: "revoked",
      version: record.expectedVersion + 1,
    }),
    idFactory: () => generated.shift(),
    clock: () => new Date(requestedAt),
    ...overrides,
  });
}

test("revocation IDs use distinct opaque event and correlation namespaces", () => {
  const generated = [
    "018f1234-5678-7abc-8def-0123456789e1",
    "018f1234-5678-7abc-8def-0123456789f1",
  ];
  assert.deepEqual(createCertificateRevocationIds(() => generated.shift()), {
    eventId: ids.event,
    correlationId: ids.correlation,
  });
});

test("normalization derives tenant, actor, time and permanent CA reason from trusted context", () => {
  const normalized = normalizeCertificateRevocationRequest({
    context: context(), request: request(), clock: () => new Date(requestedAt),
  });
  assert.equal(normalized.tenantId, ids.tenant);
  assert.equal(normalized.requestedBySubjectId, ids.alice);
  assert.equal(normalized.requestedAt, requestedAt);
  assert.equal(normalized.caReasonCode, "KeyCompromise");
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal("issuerId" in normalized, false);
  assert.equal("subjectId" in normalized, false);
});

test("requests cannot select trusted fields or reversible hold semantics", () => {
  for (const candidate of [
    request({ tenantId: ids.tenant }),
    request({ subjectId: ids.alice }),
    request({ issuerId: ids.issuer }),
    request({ reasonCode: "CERTIFICATE_HOLD" }),
    request({ revokedAt: requestedAt }),
  ]) {
    assert.throws(
      () => normalizeCertificateRevocationRequest({ context: context(), request: candidate }),
      CertificateRevocationError,
    );
  }
  assert.equal(Object.hasOwn(REVOCATION_REASON_CODES, "CERTIFICATE_HOLD"), false);
});

test("the certificate owner and same-tenant administrator can prepare exact issuer-bound revocation", async () => {
  const owner = await prepareCertificateRevocation({
    context: context(),
    request: request(),
    loadCertificate: async () => certificate(),
    resolveIssuer: async () => issuer(),
    clock: () => new Date(requestedAt),
  });
  assert.equal(owner.revocationInstruction.subjectId, ids.alice);
  assert.equal(owner.revocationInstruction.serialNumber, certificate().serialNumber);
  assert.equal(owner.revocationInstruction.caReasonCode, "KeyCompromise");

  const administrator = await prepareCertificateRevocation({
    context: context({ subjectId: ids.bob, roles: ["tenant-admin"] }),
    request: request(),
    loadCertificate: async () => certificate(),
    resolveIssuer: async () => issuer(),
    clock: () => new Date(requestedAt),
  });
  assert.equal(administrator.target.subjectId, ids.alice);
});

test("ordinary members, foreign bindings, inactive certificates and wrong issuers fail closed", async () => {
  const cases = [
    { context: context({ subjectId: ids.bob }), certificate: certificate(), issuer: issuer(), reason: "CERTIFICATE_REVOCATION_UNAUTHORIZED" },
    { context: context(), certificate: certificate({ tenantId: ids.foreignTenant }), issuer: issuer(), reason: "CERTIFICATE_INELIGIBLE" },
    { context: context(), certificate: certificate({ state: "revoked" }), issuer: issuer(), reason: "CERTIFICATE_INELIGIBLE" },
    { context: context(), certificate: certificate(), issuer: issuer({ issuerId: ids.foreignIssuer }), reason: "ACTIVE_ISSUER_REQUIRED" },
    { context: context(), certificate: certificate(), issuer: issuer({ allowedCertificateOperations: ["issue", "renew"] }), reason: "ACTIVE_ISSUER_REQUIRED" },
  ];
  for (const candidate of cases) {
    await assert.rejects(
      prepareCertificateRevocation({
        context: candidate.context,
        request: request(),
        loadCertificate: async () => candidate.certificate,
        resolveIssuer: async () => candidate.issuer,
        clock: () => new Date(requestedAt),
      }),
      (error) => error instanceof CertificateRevocationError && error.reasonCode === candidate.reason,
    );
  }
});

test("issuer confirmation precedes the atomic reasoned inventory record", async () => {
  const calls = [];
  let written;
  const result = await service({
    revokeAtIssuer: async (instruction) => {
      calls.push("issuer");
      assert.equal(instruction.tenantId, ids.tenant);
      assert.equal(instruction.certificateId, ids.certificate);
      assert.equal(instruction.reasonCode, "KEY_COMPROMISE");
      return confirmation();
    },
    recordRevocation: async (record) => {
      calls.push("database");
      written = record;
      return {
        certificateId: record.certificateId,
        eventId: record.eventId,
        correlationId: record.correlationId,
        state: "revoked",
        version: 2,
      };
    },
  }).revoke({ context: context(), request: request() });

  assert.deepEqual(calls, ["issuer", "database"]);
  assert.equal(written.causationEventId, ids.lastEvent);
  assert.equal(written.reasonCode, "KEY_COMPROMISE");
  assert.equal(written.issuerConfirmationId, "step-ca:revocation:0001");
  assert.equal(result.state, "revoked");
  assert.equal(result.eventId, ids.event);
  assert.equal(result.replayed, false);
  assert.equal("privateKey" in written, false);
});

test("issuer failure or a mismatched confirmation cannot write revoked state", async () => {
  let writes = 0;
  await assert.rejects(
    service({
      revokeAtIssuer: async () => { throw new Error("issuer unavailable"); },
      recordRevocation: async () => { writes += 1; },
    }).revoke({ context: context(), request: request() }),
    /issuer unavailable/u,
  );
  for (const invalidConfirmation of [
    confirmation({ certificateId: "crt_018f1234-5678-7abc-8def-0123456789d1" }),
    confirmation({ revokedAt: "2026-09-15T09:00:02.001Z" }),
  ]) {
    await assert.rejects(
      service({
        revokeAtIssuer: async () => invalidConfirmation,
        recordRevocation: async () => { writes += 1; },
      }).revoke({ context: context(), request: request() }),
      (error) => error instanceof CertificateRevocationError && error.reasonCode === "ISSUER_CONFIRMATION_INVALID",
    );
  }
  assert.equal(writes, 0);
});

test("an identical durable retry skips the issuer while conflicting reuse is denied", async () => {
  let issuerCalls = 0;
  const existing = {
    tenantId: ids.tenant,
    certificateId: ids.certificate,
    eventId: ids.event,
    correlationId: ids.correlation,
    requestId: ids.request,
    reasonCode: "KEY_COMPROMISE",
    requestedBySubjectId: ids.alice,
    issuerConfirmationId: "step-ca:revocation:0001",
    revokedAt: "2026-09-15T09:00:01.000Z",
    state: "revoked",
    version: 2,
  };
  const replayed = await service({
    loadExistingRevocation: async () => existing,
    revokeAtIssuer: async () => { issuerCalls += 1; },
  }).revoke({ context: context(), request: request() });
  assert.equal(replayed.eventId, ids.event);
  assert.equal(replayed.replayed, true);
  assert.equal(issuerCalls, 0);

  await assert.rejects(
    service({ loadExistingRevocation: async () => ({ ...existing, reasonCode: "CA_COMPROMISE" }) })
      .revoke({ context: context(), request: request() }),
    (error) => error instanceof CertificateRevocationError && error.reasonCode === "IDEMPOTENCY_CONFLICT",
  );
});

test("PostgreSQL repository methods use bound parameters and normalize durable rows", async () => {
  const invocations = [];
  const rows = [
    [{
      tenant_id: ids.tenant,
      certificate_id: ids.certificate,
      subject_id: ids.alice,
      issuer_id: ids.issuer,
      serial_number: certificate().serialNumber,
      fingerprint_sha256: certificate().fingerprintSha256,
      state: "active",
      last_event_id: ids.lastEvent,
      version: "1",
    }],
    [],
    [{
      recorded_certificate_id: ids.certificate,
      recorded_event_id: ids.event,
      recorded_correlation_id: ids.correlation,
      recorded_state: "revoked",
      recorded_version: "2",
    }],
  ];
  const repository = createPostgresCertificateRevocationRepository({
    query: async (sql, values, options) => {
      invocations.push({ sql, values, options });
      return { rows: rows.shift() };
    },
  });
  assert.equal((await repository.loadCertificate({ tenantId: ids.tenant, certificateId: ids.certificate })).version, 1);
  assert.equal(await repository.loadExistingRevocation({ tenantId: ids.tenant, idempotencyKey: request().idempotencyKey }), null);
  const persisted = await repository.recordRevocation({
    eventId: ids.event,
    correlationId: ids.correlation,
    requestId: ids.request,
    certificateId: ids.certificate,
    reasonCode: "KEY_COMPROMISE",
    revokedAt: "2026-09-15T09:00:01.000Z",
    idempotencyKey: request().idempotencyKey,
    issuerConfirmationId: "step-ca:revocation:0001",
  });
  assert.match(invocations[0].sql, /tenant_id = \$1 AND certificate_id = \$2/u);
  assert.deepEqual(invocations[2].values, [
    ids.event,
    ids.correlation,
    ids.request,
    ids.certificate,
    "KEY_COMPROMISE",
    "2026-09-15T09:00:01.000Z",
    request().idempotencyKey,
    "step-ca:revocation:0001",
  ]);
  assert.equal(persisted.version, 2);
});

test("internal revocation errors map to one non-enumerating denial", () => {
  assert.deepEqual(certificateRevocationSafeDenial(new CertificateRevocationError("CERTIFICATE_INELIGIBLE")), CERTIFICATE_REVOCATION_DENIAL);
  assert.throws(() => certificateRevocationSafeDenial(new Error("database failure")), /database failure/u);
});
