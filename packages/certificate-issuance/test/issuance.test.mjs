import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  CERTIFICATE_ISSUANCE_DENIAL,
  CertificateIssuanceError,
  certificateIssuanceSafeDenial,
  createCertificateIssuanceService,
  normalizeCertificateIssueRequest,
  prepareCertificateIssuance,
} from "../src/index.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  alphaAdmin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  bob: "sub_018f1234-5678-7abc-8def-0123456789ad",
  alphaIssuer: "iss_018f1234-5678-7abc-8def-0123456789b4",
  betaIssuer: "iss_018f1234-5678-7abc-8def-0123456789b5",
  request: "req_018f1234-5678-7abc-8def-0123456789c2",
};
const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${"A".repeat(96)}\n-----END CERTIFICATE REQUEST-----\n`;
const csrSha256 = createHash("sha256").update(csrPem).digest("hex");
const fixedTime = () => new Date("2026-09-14T10:00:00.000Z");

function context({ tenantId = ids.alpha, subjectId = ids.alice, roles = ["tenant-member"] } = {}) {
  return resolveTenantContext({
    authentication: { source: "trusted-session", authenticationId: "session-1", tenantId, subjectId },
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
    profileId: "tenant-client-auth-v1",
    subjectId: ids.alice,
    requestedValiditySeconds: 3600,
    proofOfPossession: { publicKeyAlgorithm: "ecdsa-p256", csrPem, csrSha256 },
    idempotencyKey: "tenant-alpha:certificate:issue:0002",
    ...overrides,
  };
}

function membership(tenantId = ids.alpha, subjectId = ids.alice) {
  return { tenantId, subjectId, tenantState: "active", subjectState: "active", membershipState: "active" };
}

function issuer(tenantId = ids.alpha, issuerId = ids.alphaIssuer, issuerName = "tenant-alpha-intermediate") {
  return {
    tenantId,
    issuerId,
    issuerName,
    authorityUrl: `https://${issuerName}.internal:9000`,
    state: "active",
    allowedCertificateOperations: ["issue", "renew", "revoke"],
    issuerCertificatePem: `-----BEGIN CERTIFICATE-----\n${"A".repeat(96)}\n-----END CERTIFICATE-----\n`,
  };
}

test("normalization derives tenant, requester, operation and timestamps from trusted state", () => {
  const normalized = normalizeCertificateIssueRequest({ context: context(), request: request(), clock: fixedTime });
  assert.equal(normalized.tenantId, ids.alpha);
  assert.equal(normalized.requestedBySubjectId, ids.alice);
  assert.equal(normalized.operation, "issue");
  assert.equal(normalized.renewalOfCertificateId, null);
  assert.equal(normalized.requestedAt, "2026-09-14T10:00:00.000Z");
});

test("caller-selected tenant, requester, issuer and certificate fields are rejected", () => {
  for (const [field, value] of [
    ["tenantId", ids.beta],
    ["requestedBySubjectId", ids.alphaAdmin],
    ["issuerId", ids.betaIssuer],
    ["subjectAlternativeNames", ["urn:foreign"]],
    ["privateKey", "forbidden"],
  ]) {
    assert.throws(
      () => normalizeCertificateIssueRequest({ context: context(), request: request({ [field]: value }), clock: fixedTime }),
      (error) => error instanceof CertificateIssuanceError && error.reasonCode === "REQUEST_FIELDS_INVALID",
    );
  }
});

test("CSR digest, algorithm and bounded validity are enforced", () => {
  for (const candidate of [
    request({ proofOfPossession: { ...request().proofOfPossession, csrSha256: "0".repeat(64) } }),
    request({ proofOfPossession: { ...request().proofOfPossession, publicKeyAlgorithm: "rsa-1024" } }),
    request({ requestedValiditySeconds: 299 }),
    request({ requestedValiditySeconds: 86_401 }),
  ]) {
    assert.throws(() => normalizeCertificateIssueRequest({ context: context(), request: candidate, clock: fixedTime }), CertificateIssuanceError);
  }
});

test("members may enroll themselves and receive only a derived signing instruction", async () => {
  const prepared = await prepareCertificateIssuance({
    context: context(),
    request: request(),
    loadTargetMembership: async ({ tenantId, subjectId }) => membership(tenantId, subjectId),
    resolveIssuer: async () => issuer(),
    clock: fixedTime,
  });
  assert.deepEqual(prepared.signingInstruction.subject, { commonName: ids.alice, organizationName: ids.alpha });
  assert.deepEqual(prepared.signingInstruction.subjectAlternativeNames, [
    `urn:tenant-trust:identity:v1:tenant:${ids.alpha}:subject:${ids.alice}`,
  ]);
  assert.equal(prepared.signingInstruction.issuerId, ids.alphaIssuer);
  assert.equal(JSON.stringify(prepared.signingInstruction).includes("PRIVATE KEY"), false);
  assert.equal(Object.isFrozen(prepared.signingInstruction), true);
});

test("a tenant member cannot enroll another subject", async () => {
  await assert.rejects(
    prepareCertificateIssuance({
      context: context(),
      request: request({ subjectId: ids.alphaAdmin }),
      loadTargetMembership: async ({ tenantId, subjectId }) => membership(tenantId, subjectId),
      resolveIssuer: async () => issuer(),
      clock: fixedTime,
    }),
    (error) => error instanceof CertificateIssuanceError && error.reasonCode === "SUBJECT_ENROLLMENT_UNAUTHORIZED",
  );
});

test("a tenant administrator may enroll an active subject in the same tenant", async () => {
  const prepared = await prepareCertificateIssuance({
    context: context({ subjectId: ids.alphaAdmin, roles: ["tenant-admin"] }),
    request: request(),
    loadTargetMembership: async ({ tenantId, subjectId }) => membership(tenantId, subjectId),
    resolveIssuer: async () => issuer(),
    clock: fixedTime,
  });
  assert.equal(prepared.normalizedRequest.requestedBySubjectId, ids.alphaAdmin);
  assert.equal(prepared.normalizedRequest.subjectId, ids.alice);
});

test("foreign and inactive membership records fail before issuer resolution", async () => {
  let issuerCalled = false;
  for (const target of [membership(ids.beta, ids.bob), { ...membership(), membershipState: "suspended" }, null]) {
    await assert.rejects(
      prepareCertificateIssuance({
        context: context({ subjectId: ids.alphaAdmin, roles: ["tenant-admin"] }),
        request: request({ subjectId: ids.bob }),
        loadTargetMembership: async () => target,
        resolveIssuer: async () => { issuerCalled = true; return issuer(); },
        clock: fixedTime,
      }),
      (error) => error instanceof CertificateIssuanceError && error.reasonCode === "TARGET_MEMBERSHIP_INACTIVE",
    );
  }
  assert.equal(issuerCalled, false);
});

test("issuer resolution fails closed on a foreign tenant or inactive mapping", async () => {
  for (const mapping of [
    issuer(ids.beta, ids.betaIssuer, "tenant-beta-intermediate"),
    { ...issuer(), state: "planned" },
    { ...issuer(), authorityUrl: "http://tenant-alpha-ca.internal:9000" },
  ]) {
    await assert.rejects(
      prepareCertificateIssuance({
        context: context(),
        request: request(),
        loadTargetMembership: async ({ tenantId, subjectId }) => membership(tenantId, subjectId),
        resolveIssuer: async () => mapping,
        clock: fixedTime,
      }),
      CertificateIssuanceError,
    );
  }
});

test("internal denial reasons map to one non-enumerating response", () => {
  assert.deepEqual(certificateIssuanceSafeDenial(new CertificateIssuanceError("ISSUER_TENANT_MISMATCH")), CERTIFICATE_ISSUANCE_DENIAL);
});

test("the issuance service requires an inventory writer before it can return success", () => {
  assert.throws(
    () => createCertificateIssuanceService({ signCertificate: async () => null }),
    /certificate inventory writer/iu,
  );
});
