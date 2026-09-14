import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  buildRenewedCertificateRecord,
  CertificateInventoryError,
  createCertificateInventoryService,
  createCertificateRenewalIds,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  request: "req_018f1234-5678-7abc-8def-0123456789c8",
  oldCertificate: "crt_018f1234-5678-7abc-8def-0123456789d0",
  newCertificate: "crt_018f1234-5678-7abc-8def-0123456789d1",
  oldEvent: "evt_018f1234-5678-7abc-8def-0123456789e0",
  renewedEvent: "evt_018f1234-5678-7abc-8def-0123456789e1",
  supersededEvent: "evt_018f1234-5678-7abc-8def-0123456789e2",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789f1",
};

function context() {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "inventory-renewal", tenantId: ids.tenant, subjectId: ids.subject },
    authority: {
      tenant: { tenantId: ids.tenant, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: { tenantId: ids.tenant, subjectId: ids.subject, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

function request(overrides = {}) {
  return {
    operation: "renew",
    profileId: "tenant-client-auth-v1",
    requestId: ids.request,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    requestedBySubjectId: ids.subject,
    requestedAt: "2026-09-14T09:50:00.000Z",
    renewalOfCertificateId: ids.oldCertificate,
    idempotencyKey: "tenant-alpha:certificate:renew:0001",
    proofOfPossession: { publicKeyAlgorithm: "ecdsa-p256" },
    ...overrides,
  };
}

function predecessor(overrides = {}) {
  return {
    tenantId: ids.tenant,
    certificateId: ids.oldCertificate,
    subjectId: ids.subject,
    profileId: "tenant-client-auth-v1",
    state: "active",
    publicKeySha256: "a".repeat(64),
    lastEventId: ids.oldEvent,
    ...overrides,
  };
}

function certificate(overrides = {}) {
  return {
    certificatePem: "-----BEGIN CERTIFICATE-----\npublic-only-renewed-certificate\n-----END CERTIFICATE-----\n",
    profileId: "tenant-client-auth-v1",
    tenantId: ids.tenant,
    subjectId: ids.subject,
    issuerId: ids.issuer,
    serialNumber: "00000000000000000000000000000003",
    fingerprintSha256: "c".repeat(64),
    publicKeySha256: "b".repeat(64),
    notBefore: "2026-09-14T09:49:00.000Z",
    notAfter: "2026-09-14T10:49:00.000Z",
    ...overrides,
  };
}

const renewalIds = Object.freeze({
  certificateId: ids.newCertificate,
  renewedEventId: ids.renewedEvent,
  supersededEventId: ids.supersededEvent,
  correlationId: ids.correlation,
});

test("renewal IDs allocate distinct lifecycle events for renewal and supersession", () => {
  const values = [
    "018f1234-5678-7abc-8def-0123456789d1",
    "018f1234-5678-7abc-8def-0123456789e1",
    "018f1234-5678-7abc-8def-0123456789e2",
    "018f1234-5678-7abc-8def-0123456789f1",
  ];
  assert.deepEqual(createCertificateRenewalIds(() => values.shift()), renewalIds);
});

test("renewal records link the new certificate to the active predecessor and omit PEM", () => {
  const record = buildRenewedCertificateRecord({
    context: context(), normalizedRequest: request(), predecessor: predecessor(), verifiedCertificate: certificate(), ids: renewalIds,
  });
  assert.equal(record.supersedesCertificateId, ids.oldCertificate);
  assert.equal(record.renewedEventId, ids.renewedEvent);
  assert.equal(record.supersededEventId, ids.supersededEvent);
  assert.equal(record.predecessorLastEventId, ids.oldEvent);
  assert.equal(record.publicKeySha256, "b".repeat(64));
  assert.equal("certificatePem" in record, false);
});

test("cross-tenant, non-active and same-key renewal bindings fail closed", () => {
  for (const previous of [
    predecessor({ tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac" }),
    predecessor({ state: "revoked" }),
    predecessor({ publicKeySha256: "b".repeat(64) }),
  ]) {
    assert.throws(
      () => buildRenewedCertificateRecord({
        context: context(), normalizedRequest: request(), predecessor: previous, verifiedCertificate: certificate(), ids: renewalIds,
      }),
      (error) => error instanceof CertificateInventoryError && error.reasonCode === "RENEWAL_BINDING_MISMATCH",
    );
  }
});

test("renewal success requires confirmation of both events and predecessor supersession", async () => {
  const generated = [
    "018f1234-5678-7abc-8def-0123456789d1",
    "018f1234-5678-7abc-8def-0123456789e1",
    "018f1234-5678-7abc-8def-0123456789e2",
    "018f1234-5678-7abc-8def-0123456789f1",
  ];
  let inserted;
  const service = createCertificateInventoryService({
    idFactory: () => generated.shift(),
    insertIssuedCertificate: async () => null,
    insertRenewedCertificate: async (record) => {
      inserted = record;
      return {
        certificateId: record.certificateId,
        renewedEventId: record.renewedEventId,
        supersededEventId: record.supersededEventId,
        state: "active",
        predecessorState: "superseded",
      };
    },
  });
  const result = await service.recordRenewedCertificate({
    context: context(), normalizedRequest: request(), predecessor: predecessor(), verifiedCertificate: certificate(),
  });
  assert.equal(inserted.supersedesCertificateId, ids.oldCertificate);
  assert.equal(result.certificateId, ids.newCertificate);
  assert.equal(result.supersededEventId, ids.supersededEvent);
  assert.match(result.certificatePem, /BEGIN CERTIFICATE/u);
});

test("an incomplete atomic renewal confirmation is rejected", async () => {
  const generated = [
    "018f1234-5678-7abc-8def-0123456789d1",
    "018f1234-5678-7abc-8def-0123456789e1",
    "018f1234-5678-7abc-8def-0123456789e2",
    "018f1234-5678-7abc-8def-0123456789f1",
  ];
  const service = createCertificateInventoryService({
    idFactory: () => generated.shift(),
    insertIssuedCertificate: async () => null,
    insertRenewedCertificate: async () => ({ certificateId: ids.newCertificate, renewedEventId: ids.renewedEvent, state: "active" }),
  });
  await assert.rejects(
    service.recordRenewedCertificate({ context: context(), normalizedRequest: request(), predecessor: predecessor(), verifiedCertificate: certificate() }),
    (error) => error instanceof CertificateInventoryError && error.reasonCode === "INVENTORY_WRITE_UNCONFIRMED",
  );
});
