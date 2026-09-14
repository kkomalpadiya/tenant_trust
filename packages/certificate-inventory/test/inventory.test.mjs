import assert from "node:assert/strict";
import test from "node:test";
import {
  buildIssuedCertificateRecord,
  CertificateInventoryError,
  createCertificateInventoryIds,
  createCertificateInventoryService,
} from "../src/index.mjs";
import { resolveTenantContext } from "@tenant-trust/tenant-context";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  alphaIssuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  request: "req_018f1234-5678-7abc-8def-0123456789c2",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789d0",
  event: "evt_018f1234-5678-7abc-8def-0123456789e0",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789f0",
};

function context(overrides = {}) {
  const tenantId = overrides.tenantId ?? ids.alpha;
  const subjectId = overrides.subjectId ?? ids.alice;
  const roles = overrides.roles ?? ["tenant-member"];
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "inventory-test", tenantId, subjectId },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles,
    },
  });
}

function request(overrides = {}) {
  return Object.freeze({
    operation: "issue",
    profileId: "tenant-client-auth-v1",
    requestId: ids.request,
    tenantId: ids.alpha,
    subjectId: ids.alice,
    requestedBySubjectId: ids.alice,
    requestedAt: "2026-09-14T10:00:00.000Z",
    idempotencyKey: "tenant-alpha:certificate:issue:0004",
    proofOfPossession: Object.freeze({ publicKeyAlgorithm: "ecdsa-p256" }),
    ...overrides,
  });
}

function certificate(overrides = {}) {
  return Object.freeze({
    certificatePem: "-----BEGIN CERTIFICATE-----\npublic-only-test-certificate\n-----END CERTIFICATE-----\n",
    profileId: "tenant-client-auth-v1",
    tenantId: ids.alpha,
    subjectId: ids.alice,
    issuerId: ids.alphaIssuer,
    serialNumber: "00000000000000000000000000000001",
    fingerprintSha256: "a".repeat(64),
    notBefore: "2026-09-14T09:59:00.000Z",
    notAfter: "2026-09-14T10:59:00.000Z",
    ...overrides,
  });
}

const inventoryIds = Object.freeze({
  certificateId: ids.certificate,
  eventId: ids.event,
  correlationId: ids.correlation,
});

test("inventory IDs use opaque certificate, event and correlation namespaces", () => {
  const uuids = [
    "018f1234-5678-7abc-8def-0123456789d0",
    "018f1234-5678-7abc-8def-0123456789e0",
    "018f1234-5678-7abc-8def-0123456789f0",
  ];
  assert.deepEqual(createCertificateInventoryIds(() => uuids.shift()), inventoryIds);
});

test("issued metadata becomes one immutable active inventory record", () => {
  const record = buildIssuedCertificateRecord({
    context: context(),
    normalizedRequest: request(),
    verifiedCertificate: certificate(),
    ids: inventoryIds,
  });
  assert.equal(record.tenantId, ids.alpha);
  assert.equal(record.certificateId, ids.certificate);
  assert.equal(record.issuedEventId, ids.event);
  assert.equal(record.lastEventId, ids.event);
  assert.equal(record.state, "active");
  assert.equal(record.supersedesCertificateId, null);
  assert.equal(Object.isFrozen(record), true);
  assert.equal("certificatePem" in record, false);
});

test("trusted request, context and verified certificate must keep the same tenant and subject", () => {
  for (const candidate of [
    { context: context({ tenantId: ids.beta }), normalizedRequest: request(), verifiedCertificate: certificate() },
    { context: context(), normalizedRequest: request({ tenantId: ids.beta }), verifiedCertificate: certificate() },
    { context: context(), normalizedRequest: request(), verifiedCertificate: certificate({ tenantId: ids.beta }) },
  ]) {
    assert.throws(
      () => buildIssuedCertificateRecord({ ...candidate, ids: inventoryIds }),
      (error) => error instanceof CertificateInventoryError && error.reasonCode === "ISSUANCE_BINDING_MISMATCH",
    );
  }
});

test("invalid serials, fingerprints and validity windows are rejected", () => {
  for (const verifiedCertificate of [
    certificate({ serialNumber: "0".repeat(32) }),
    certificate({ fingerprintSha256: "A".repeat(64) }),
    certificate({ notAfter: "2026-09-14T10:00:00.000Z" }),
  ]) {
    assert.throws(
      () => buildIssuedCertificateRecord({ context: context(), normalizedRequest: request(), verifiedCertificate, ids: inventoryIds }),
      CertificateInventoryError,
    );
  }
});

test("the inventory service returns success only after the repository confirms both durable IDs", async () => {
  const generated = [
    "018f1234-5678-7abc-8def-0123456789d0",
    "018f1234-5678-7abc-8def-0123456789e0",
    "018f1234-5678-7abc-8def-0123456789f0",
  ];
  let inserted;
  const service = createCertificateInventoryService({
    idFactory: () => generated.shift(),
    insertIssuedCertificate: async (record) => {
      inserted = record;
      return { certificateId: record.certificateId, eventId: record.issuedEventId, state: record.state };
    },
  });
  const result = await service.recordIssuedCertificate({
    context: context(),
    normalizedRequest: request(),
    verifiedCertificate: certificate(),
  });
  assert.equal(inserted.fingerprintSha256, "a".repeat(64));
  assert.equal(result.certificateId, ids.certificate);
  assert.match(result.certificatePem, /BEGIN CERTIFICATE/u);
});

test("an identical replay adopts the durable IDs returned by the repository", async () => {
  const generated = [
    "018f1234-5678-7abc-8def-0123456789d2",
    "018f1234-5678-7abc-8def-0123456789e2",
    "018f1234-5678-7abc-8def-0123456789f2",
  ];
  const service = createCertificateInventoryService({
    idFactory: () => generated.shift(),
    insertIssuedCertificate: async () => ({
      certificateId: ids.certificate,
      eventId: ids.event,
      state: "active",
    }),
  });
  const result = await service.recordIssuedCertificate({
    context: context(),
    normalizedRequest: request(),
    verifiedCertificate: certificate(),
  });
  assert.equal(result.certificateId, ids.certificate);
  assert.equal(result.issuedEventId, ids.event);
  assert.equal(result.lastEventId, ids.event);
});

test("a missing or unconfirmed repository write fails closed", async () => {
  assert.throws(() => createCertificateInventoryService(), TypeError);
  const generated = [
    "018f1234-5678-7abc-8def-0123456789d0",
    "018f1234-5678-7abc-8def-0123456789e0",
    "018f1234-5678-7abc-8def-0123456789f0",
  ];
  const service = createCertificateInventoryService({
    idFactory: () => generated.shift(),
    insertIssuedCertificate: async () => null,
  });
  await assert.rejects(
    service.recordIssuedCertificate({ context: context(), normalizedRequest: request(), verifiedCertificate: certificate() }),
    (error) => error instanceof CertificateInventoryError && error.reasonCode === "INVENTORY_WRITE_UNCONFIRMED",
  );
});
