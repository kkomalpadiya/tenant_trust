import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CertificateIssuanceError,
  createCertificateIssuanceService,
  normalizeCertificateRenewalRequest,
  prepareCertificateRenewal,
} from "../src/index.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  request: "req_018f1234-5678-7abc-8def-0123456789c8",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789d0",
};
const oldKey = "a".repeat(64);
const newKey = "b".repeat(64);
const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${"B".repeat(96)}\n-----END CERTIFICATE REQUEST-----\n`;
const csrSha256 = createHash("sha256").update(csrPem).digest("hex");

function context() {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "renewal-test", tenantId: ids.alpha, subjectId: ids.alice },
    authority: {
      tenant: { tenantId: ids.alpha, state: "active", version: 1 },
      subject: { subjectId: ids.alice, state: "active", version: 1 },
      membership: { tenantId: ids.alpha, subjectId: ids.alice, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

function request(overrides = {}) {
  return {
    requestId: ids.request,
    profileId: "tenant-client-auth-v1",
    subjectId: ids.alice,
    requestedValiditySeconds: 3600,
    proofOfPossession: { publicKeyAlgorithm: "ecdsa-p256", csrPem, csrSha256 },
    renewalOfCertificateId: ids.certificate,
    idempotencyKey: "tenant-alpha:certificate:renew:0001",
    ...overrides,
  };
}

function membership(overrides = {}) {
  return {
    tenantId: ids.alpha,
    subjectId: ids.alice,
    tenantState: "active",
    subjectState: "active",
    membershipState: "active",
    ...overrides,
  };
}

function predecessor(overrides = {}) {
  return {
    tenantId: ids.alpha,
    certificateId: ids.certificate,
    subjectId: ids.alice,
    profileId: "tenant-client-auth-v1",
    state: "active",
    publicKeySha256: oldKey,
    notBefore: "2026-09-14T09:00:00.000Z",
    notAfter: "2026-09-14T10:00:00.000Z",
    lastEventId: "evt_018f1234-5678-7abc-8def-0123456789e0",
    ...overrides,
  };
}

function issuer() {
  return {
    tenantId: ids.alpha,
    issuerId: ids.issuer,
    issuerName: "tenant-alpha-intermediate",
    authorityUrl: "https://tenant-alpha-ca.internal:9000",
    state: "active",
    allowedCertificateOperations: ["issue", "renew", "revoke"],
    issuerCertificatePem: `-----BEGIN CERTIFICATE-----\n${"A".repeat(96)}\n-----END CERTIFICATE-----\n`,
  };
}

const eligibleTime = () => new Date("2026-09-14T09:50:00.000Z");

test("renewal normalization derives the operation and tenant actor while accepting only a predecessor ID", () => {
  const normalized = normalizeCertificateRenewalRequest({ context: context(), request: request(), clock: eligibleTime });
  assert.equal(normalized.operation, "renew");
  assert.equal(normalized.tenantId, ids.alpha);
  assert.equal(normalized.requestedBySubjectId, ids.alice);
  assert.equal(normalized.renewalOfCertificateId, ids.certificate);
  assert.throws(
    () => normalizeCertificateRenewalRequest({ context: context(), request: request({ issuerId: ids.issuer }), clock: eligibleTime }),
    CertificateIssuanceError,
  );
});

test("an active certificate in its final validity quarter prepares a fresh-key renewal", async () => {
  const prepared = await prepareCertificateRenewal({
    context: context(),
    request: request(),
    loadTargetMembership: async () => membership(),
    loadRenewalCertificate: async () => predecessor(),
    inspectCertificateRequest: async () => ({ publicKeyAlgorithm: "ecdsa-p256", publicKeySha256: newKey }),
    resolveIssuer: async () => issuer(),
    clock: eligibleTime,
  });
  assert.equal(prepared.signingInstruction.operation, "renew");
  assert.equal(prepared.signingInstruction.renewalOfCertificateId, ids.certificate);
  assert.equal(prepared.signingInstruction.rotatesFromPublicKeySha256, oldKey);
  assert.equal(prepared.signingInstruction.publicKeySha256, newKey);
  assert.equal(Object.isFrozen(prepared.signingInstruction), true);
});

test("early, expired, revoked and superseded certificates cannot be renewed", async () => {
  for (const [candidate, clock, reasonCode] of [
    [predecessor(), () => new Date("2026-09-14T09:30:00.000Z"), "RENEWAL_WINDOW_CLOSED"],
    [predecessor(), () => new Date("2026-09-14T10:00:00.000Z"), "RENEWAL_WINDOW_CLOSED"],
    [predecessor({ state: "revoked" }), eligibleTime, "RENEWAL_CERTIFICATE_INELIGIBLE"],
    [predecessor({ state: "superseded" }), eligibleTime, "RENEWAL_CERTIFICATE_INELIGIBLE"],
  ]) {
    await assert.rejects(
      prepareCertificateRenewal({
        context: context(), request: request(),
        loadTargetMembership: async () => membership(),
        loadRenewalCertificate: async () => candidate,
        inspectCertificateRequest: async () => ({ publicKeyAlgorithm: "ecdsa-p256", publicKeySha256: newKey }),
        resolveIssuer: async () => issuer(), clock,
      }),
      (error) => error instanceof CertificateIssuanceError && error.reasonCode === reasonCode,
    );
  }
});

test("suspended identities and memberships fail before certificate lookup or signing", async () => {
  let certificateLoaded = false;
  for (const target of [membership({ subjectState: "suspended" }), membership({ membershipState: "suspended" })]) {
    await assert.rejects(
      prepareCertificateRenewal({
        context: context(), request: request(),
        loadTargetMembership: async () => target,
        loadRenewalCertificate: async () => { certificateLoaded = true; return predecessor(); },
        inspectCertificateRequest: async () => ({ publicKeyAlgorithm: "ecdsa-p256", publicKeySha256: newKey }),
        resolveIssuer: async () => issuer(), clock: eligibleTime,
      }),
      (error) => error instanceof CertificateIssuanceError && error.reasonCode === "TARGET_MEMBERSHIP_INACTIVE",
    );
  }
  assert.equal(certificateLoaded, false);
});

test("reusing the predecessor key is denied before issuer resolution", async () => {
  let issuerCalled = false;
  await assert.rejects(
    prepareCertificateRenewal({
      context: context(), request: request(),
      loadTargetMembership: async () => membership(),
      loadRenewalCertificate: async () => predecessor(),
      inspectCertificateRequest: async () => ({ publicKeyAlgorithm: "ecdsa-p256", publicKeySha256: oldKey }),
      resolveIssuer: async () => { issuerCalled = true; return issuer(); },
      clock: eligibleTime,
    }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "KEY_ROTATION_REQUIRED",
  );
  assert.equal(issuerCalled, false);
});

test("the service exposes renewal only when a renewal inventory writer is configured", async () => {
  const service = createCertificateIssuanceService({
    loadTargetMembership: async () => membership(),
    resolveIssuer: async () => issuer(),
    signCertificate: async () => null,
    recordIssuedCertificate: async () => null,
  });
  await assert.rejects(service.renew({ context: context(), request: request() }), /renewal inventory writer/iu);
});
