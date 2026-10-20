import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  AccessDeniedError,
  REQUEST_SAFEGUARD_POLICY,
  REQUEST_STATE_POLICY,
  createRequestAuditRecorder,
  createTenantTrustApi as createTenantTrustApiWithAudit,
} from "../src/index.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const requestAuditRecorder = createRequestAuditRecorder({ async write() {} });

function createTenantTrustApi(options) {
  return createTenantTrustApiWithAudit({ requestAuditRecorder, ...options });
}

const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: "sha256:alpha-admin",
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
});

const recordIds = Object.freeze([
  "res_018f1234-5678-7abc-8def-0123456789b0",
  "res_018f1234-5678-7abc-8def-0123456789b1",
]);
const idempotencyKey = "idem_018f1234-5678-4abc-8def-0123456789a1";

function createRepository(overrides = {}) {
  return {
    authorizationMode,
    requestSafeguardPolicy: REQUEST_SAFEGUARD_POLICY,
    requestStatePolicy: REQUEST_STATE_POLICY,
    async getProfile() { return {}; },
    async listRecords() { return []; },
    async getRecord() { return {}; },
    async exportRecords() { return {}; },
    async reviewMembership() { return {}; },
    ...overrides,
  };
}

test("export accepts only a bounded record-ID list and trusted authentication", async (t) => {
  let observed;
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => authentication },
    repository: createRepository({
      async exportRecords(resolvedAuthentication, requestedRecordIds) {
        observed = { resolvedAuthentication, requestedRecordIds };
        return {
          operation: { operationId: "op_018f1234-5678-4abc-8def-0123456789b2" },
          records: [],
        };
      },
    }),
  });
  t.after(() => api.close());

  const response = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: {
      "idempotency-key": idempotencyKey,
      "x-tenant-id": "tnt_018f1234-5678-7abc-8def-0123456789ff",
      "x-subject-id": "sub_018f1234-5678-7abc-8def-0123456789ff",
    },
    payload: { recordIds },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(observed, {
    resolvedAuthentication: authentication,
    requestedRecordIds: [...recordIds],
  });
  assert.match(response.json().operation.operationId, /^op_/u);
});

test("membership review accepts one validated subject and no caller-selected tenant", async (t) => {
  let observed;
  const targetSubjectId = "sub_018f1234-5678-7abc-8def-0123456789ab";
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => authentication },
    repository: createRepository({
      async reviewMembership(resolvedAuthentication, subjectId) {
        observed = { resolvedAuthentication, subjectId };
        return {
          operation: { operationId: "op_018f1234-5678-4abc-8def-0123456789b3" },
          membership: { subjectId },
        };
      },
    }),
  });
  t.after(() => api.close());

  const response = await api.inject({
    method: "POST",
    url: "/v1/admin/membership-reviews",
    headers: { "idempotency-key": idempotencyKey },
    payload: { subjectId: targetSubjectId },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(observed, { resolvedAuthentication: authentication, subjectId: targetSubjectId });

  const injectedTenant = await api.inject({
    method: "POST",
    url: "/v1/admin/membership-reviews",
    headers: { "idempotency-key": idempotencyKey },
    payload: { subjectId: targetSubjectId, tenantId: authentication.tenantId },
  });
  assert.equal(injectedTenant.statusCode, 400);
  assert.deepEqual(injectedTenant.json(), { error: { code: "INVALID_REQUEST" } });
});

test("sensitive schemas reject oversized batches, duplicates and query controls before authentication", async (t) => {
  let authenticationAttempts = 0;
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => {
      authenticationAttempts += 1;
      return authentication;
    } },
    repository: createRepository(),
  });
  t.after(() => api.close());

  const tooMany = Array.from({ length: 26 }, (_, index) => (
    `res_00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`
  ));
  for (const options of [
    { url: "/v1/tenant-records/export", payload: { recordIds: tooMany } },
    { url: "/v1/tenant-records/export", payload: { recordIds: [recordIds[0], recordIds[0]] } },
    { url: "/v1/tenant-records/export?tenantId=tnt_other", payload: { recordIds: [recordIds[0]] } },
  ]) {
    const response = await api.inject({ method: "POST", ...options });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: { code: "INVALID_REQUEST" } });
  }
  assert.equal(authenticationAttempts, 0);
});

test("sensitive request bodies are capped at four KiB", async (t) => {
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => authentication },
    repository: createRepository(),
  });
  t.after(() => api.close());

  const response = await api.inject({
    method: "POST",
    url: "/v1/admin/membership-reviews",
    headers: { "content-type": "application/json", "idempotency-key": idempotencyKey },
    payload: JSON.stringify({ subjectId: authentication.subjectId, padding: "x".repeat(4_096) }),
  });
  assert.equal(response.statusCode, 413);
  assert.deepEqual(response.json(), { error: { code: "REQUEST_TOO_LARGE" } });
});

test("authorization denials remain uniform and non-enumerating", async (t) => {
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => authentication },
    repository: createRepository({
      async exportRecords() { throw new AccessDeniedError(); },
      async reviewMembership() { throw new AccessDeniedError(); },
    }),
  });
  t.after(() => api.close());

  for (const options of [
    { url: "/v1/tenant-records/export", payload: { recordIds: [recordIds[0]] } },
    { url: "/v1/admin/membership-reviews", payload: { subjectId: authentication.subjectId } },
  ]) {
    const response = await api.inject({
      method: "POST",
      headers: { "idempotency-key": idempotencyKey },
      ...options,
    });
    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.json(), { error: { code: "ACCESS_DENIED" } });
    assert.doesNotMatch(response.body, /tenant|subject|record|operation/u);
  }
});

test("step-up challenge routes use the mTLS subject and return only opaque challenge and proof material", async (t) => {
  const factorId = "suf_018f1234-5678-7abc-8def-0123456789d1";
  const challengeId = "suc_018f1234-5678-7abc-8def-0123456789d2";
  const signatureBase64url = "A".repeat(86);
  const observed = [];
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => authentication },
    repository: createRepository({
      async issueStepUpChallenge(resolved, action, selectedFactorId) {
        observed.push({ kind: "issue", resolved, action, selectedFactorId });
        return { challengeId, factorId, action, sessionId: "sus_018f1234-5678-7abc-8def-0123456789d3" };
      },
      async verifyStepUpChallenge(resolved, selectedChallengeId, signature) {
        observed.push({ kind: "verify", resolved, selectedChallengeId, signature });
        return { proofId: "sup_018f1234-5678-7abc-8def-0123456789d4", action: "record:export" };
      },
    }),
  });
  t.after(() => api.close());

  const challenge = await api.inject({
    method: "POST",
    url: "/v1/step-up/challenges",
    payload: { action: "record:export", factorId },
  });
  assert.equal(challenge.statusCode, 200);
  assert.equal(challenge.json().stepUpChallenge.challengeId, challengeId);

  const verification = await api.inject({
    method: "POST",
    url: `/v1/step-up/challenges/${challengeId}/verifications`,
    payload: { signatureBase64url },
  });
  assert.equal(verification.statusCode, 200);
  assert.match(verification.json().stepUpProof.proofId, /^sup_/u);
  assert.deepEqual(observed, [
    { kind: "issue", resolved: authentication, action: "record:export", selectedFactorId: factorId },
    { kind: "verify", resolved: authentication, selectedChallengeId: challengeId, signature: signatureBase64url },
  ]);
});

test("a sensitive request forwards the opaque proof and session only to the repository", async (t) => {
  let presentation;
  const api = createTenantTrustApi({
    identityResolver: { resolve: async () => authentication },
    repository: createRepository({
      async exportRecords(_authentication, _recordIds, options) {
        presentation = options.policyRequest.stepUpPresentation;
        return { operation: { operationId: "op_018f1234-5678-7abc-8def-0123456789d5" }, records: [] };
      },
    }),
  });
  t.after(() => api.close());
  const proofId = "sup_018f1234-5678-7abc-8def-0123456789d6";
  const sessionId = "sus_018f1234-5678-7abc-8def-0123456789d7";
  const response = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: {
      "idempotency-key": idempotencyKey,
      "x-step-up-proof": proofId,
      "x-step-up-session": sessionId,
    },
    payload: { recordIds: [recordIds[0]] },
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(presentation, { proofId, sessionId });
  assert.doesNotMatch(response.body, /sup_|sus_/u);
});
