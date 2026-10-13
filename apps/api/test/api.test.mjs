import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import { GatewayIdentityError } from "@tenant-trust/gateway-identity";
import {
  AccessDeniedError,
  CertificateNotAcceptedError,
  POLICY_ENFORCEMENT_POLICY,
  REQUEST_SAFEGUARD_POLICY,
  REQUEST_STATE_POLICY,
  RequestStateUnavailableError,
  createGatewayRequestAuthenticator,
  createRequestAuditRecorder,
  createTenantTrustApi as createTenantTrustApiWithAudit,
} from "../src/index.mjs";

const alphaAuthentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: "sha256:alpha",
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
});
const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const requestAuditRecorder = createRequestAuditRecorder({ async write() {} });

function createTenantTrustApi(options) {
  return createTenantTrustApiWithAudit({ requestAuditRecorder, ...options });
}

function createRepository(overrides = {}) {
  return {
    authorizationMode,
    requestSafeguardPolicy: REQUEST_SAFEGUARD_POLICY,
    requestStatePolicy: REQUEST_STATE_POLICY,
    async getProfile(authentication) {
      return { tenantId: authentication.tenantId, subjectId: authentication.subjectId };
    },
    async listRecords(authentication) {
      return [{ recordId: "res_018f1234-5678-7abc-8def-0123456789b0", tenant: authentication.tenantId }];
    },
    async getRecord(authentication, recordId) {
      return { recordId, tenant: authentication.tenantId };
    },
    async exportRecords(authentication, recordIds) {
      return { operation: { operationId: "op_test" }, authentication, recordIds };
    },
    async reviewMembership(authentication, subjectId) {
      return { operation: { operationId: "op_test" }, authentication, subjectId };
    },
    ...overrides,
  };
}

test("API construction requires a branded internal authorization mode", () => {
  assert.throws(
    () => createTenantTrustApi({
      identityResolver: createIdentityResolver(),
      repository: { ...createRepository(), authorizationMode: { ...authorizationMode } },
    }),
    /explicit supported authorization mode/u,
  );
});

test("API construction requires the fixed authoritative request-state policy", () => {
  assert.throws(
    () => createTenantTrustApi({
      identityResolver: createIdentityResolver(),
      repository: { ...createRepository(), requestStatePolicy: { ...REQUEST_STATE_POLICY } },
    }),
    /authoritative per-request state revalidation/u,
  );
});

test("API construction requires the fixed request safeguard policy", () => {
  assert.throws(
    () => createTenantTrustApi({
      identityResolver: createIdentityResolver(),
      repository: { ...createRepository(), requestSafeguardPolicy: { ...REQUEST_SAFEGUARD_POLICY } },
    }),
    /fixed request safeguard policy/u,
  );
});

test("every protected route supplies one immutable policy request to adaptive enforcement", async (t) => {
  const adaptiveMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA);
  const observed = [];
  const capture = (name, options) => {
    observed.push({ name, policyRequest: options.policyRequest });
  };
  const repository = createRepository({
    authorizationMode: adaptiveMode,
    policyEnforcementPolicy: POLICY_ENFORCEMENT_POLICY,
    async getProfile(authentication, options) {
      capture("profile", options);
      return { tenantId: authentication.tenantId, subjectId: authentication.subjectId };
    },
    async listRecords(_authentication, options) {
      capture("records", options);
      return [];
    },
    async getRecord(authentication, recordId, options) {
      capture("record", options);
      return { recordId, ownerSubjectId: authentication.subjectId };
    },
    async exportRecords(_authentication, _recordIds, options) {
      capture("export", options);
      return { operation: { operationId: "op_018f1234-5678-7abc-8def-0123456789ab" }, records: [] };
    },
    async reviewMembership(_authentication, subjectId, options) {
      capture("review", options);
      return {
        operation: { operationId: "op_018f1234-5678-7abc-8def-0123456789ab" },
        membership: { subjectId },
      };
    },
  });
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(),
    repository,
    clock: () => new Date("2026-10-13T09:00:00.000Z"),
  });
  t.after(() => api.close());

  const recordId = "res_018f1234-5678-7abc-8def-0123456789b0";
  const subjectId = "sub_018f1234-5678-7abc-8def-0123456789ac";
  const requests = [
    { method: "GET", url: "/v1/profile" },
    { method: "GET", url: "/v1/tenant-records" },
    { method: "GET", url: `/v1/tenant-records/${recordId}` },
    {
      method: "POST",
      url: "/v1/tenant-records/export",
      headers: { "idempotency-key": "idem_018f1234-5678-7abc-8def-0123456789a1" },
      payload: { recordIds: [recordId] },
    },
    {
      method: "POST",
      url: "/v1/admin/membership-reviews",
      headers: { "idempotency-key": "idem_018f1234-5678-7abc-8def-0123456789a2" },
      payload: { subjectId },
    },
  ];
  for (const request of requests) {
    const response = await api.inject(request);
    assert.equal(response.statusCode, 200, `${request.method} ${request.url}: ${response.body}`);
  }

  assert.deepEqual(observed.map(({ name }) => name), ["profile", "records", "record", "export", "review"]);
  assert.deepEqual(observed.map(({ policyRequest }) => policyRequest.routeTemplate), [
    "/v1/profile",
    "/v1/tenant-records",
    "/v1/tenant-records/{recordid}",
    "/v1/tenant-records/export",
    "/v1/admin/membership-reviews",
  ]);
  for (const { policyRequest } of observed) {
    assert.match(policyRequest.requestId, /^req_/u);
    assert.match(policyRequest.correlationId, /^cor_/u);
    assert.match(policyRequest.resourceIdHashSha256, /^[0-9a-f]{64}$/u);
    assert.equal(policyRequest.requestedAt, "2026-10-13T09:00:00.000Z");
    assert.ok(Object.isFrozen(policyRequest));
  }
});

test("callers cannot select an authorization mode through query input", async (t) => {
  let authenticationAttempts = 0;
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(async () => {
      authenticationAttempts += 1;
      return alphaAuthentication;
    }),
    repository: createRepository(),
  });
  t.after(() => api.close());

  for (const url of [
    "/v1/profile?authorizationMode=adaptive-trust-v1",
    "/v1/tenant-records?mode=pki-rbac-baseline-v1",
    "/v1/tenant-records/res_018f1234-5678-7abc-8def-0123456789b0?mode=other",
  ]) {
    const response = await api.inject({ method: "GET", url });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: { code: "INVALID_REQUEST" } });
  }
  assert.equal(authenticationAttempts, 0);
});

function createIdentityResolver(resolve = async () => alphaAuthentication) {
  return { resolve };
}

test("profile and tenant-record routes use only the authenticated tenant identity", async (t) => {
  const observed = [];
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(),
    repository: createRepository({
      async getProfile(authentication) {
        observed.push(authentication);
        return { tenantId: authentication.tenantId, subjectId: authentication.subjectId };
      },
      async listRecords(authentication) {
        observed.push(authentication);
        return [];
      },
    }),
  });
  t.after(() => api.close());

  const forgedHeaders = {
    "x-tenant-id": "tnt_018f1234-5678-7abc-8def-0123456789ac",
    "x-subject-id": "sub_018f1234-5678-7abc-8def-0123456789ad",
    "tenant-trust-client-verification": "SUCCESS",
  };
  const profile = await api.inject({ method: "GET", url: "/v1/profile", headers: forgedHeaders });
  const records = await api.inject({ method: "GET", url: "/v1/tenant-records", headers: forgedHeaders });

  assert.equal(profile.statusCode, 200);
  assert.equal(records.statusCode, 200);
  assert.deepEqual(observed, [alphaAuthentication, alphaAuthentication]);
  assert.equal(profile.json().profile.tenantId, alphaAuthentication.tenantId);
});

test("record reads pass only an opaque record ID plus certificate authentication", async (t) => {
  let observed;
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(),
    repository: createRepository({
      async getRecord(authentication, recordId) {
        observed = { authentication, recordId };
        return { recordId, ownerSubjectId: authentication.subjectId };
      },
    }),
  });
  t.after(() => api.close());

  const response = await api.inject({
    method: "GET",
    url: "/v1/tenant-records/res_018f1234-5678-7abc-8def-0123456789b0",
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(observed, {
    authentication: alphaAuthentication,
    recordId: "res_018f1234-5678-7abc-8def-0123456789b0",
  });
});

test("malformed record identifiers are rejected before authentication or data access", async (t) => {
  let touched = false;
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(async () => {
      touched = true;
      return alphaAuthentication;
    }),
    repository: createRepository(),
  });
  t.after(() => api.close());

  const response = await api.inject({ method: "GET", url: "/v1/tenant-records/not-a-record" });
  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.json(), { error: { code: "INVALID_REQUEST" } });
  assert.equal(touched, false);
});

test("missing certificate identity returns a uniform authentication denial", async (t) => {
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(async () => {
      throw new GatewayIdentityError("FORWARDED_HEADER_INVALID");
    }),
    repository: createRepository(),
  });
  t.after(() => api.close());

  const response = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.json(), { error: { code: "CLIENT_CERTIFICATE_REQUIRED" } });
});

test("missing, foreign and unauthorized records share one non-enumerating denial", async (t) => {
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(),
    repository: createRepository({
      async getRecord() {
        throw new AccessDeniedError();
      },
    }),
  });
  t.after(() => api.close());

  const response = await api.inject({
    method: "GET",
    url: "/v1/tenant-records/res_018f1234-5678-7abc-8def-0123456789b2",
  });
  assert.equal(response.statusCode, 403);
  assert.deepEqual(response.json(), { error: { code: "ACCESS_DENIED" } });
});

test("unexpected repository failures fail closed without leaking details", async (t) => {
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(),
    repository: createRepository({
      async listRecords() {
        throw new Error("password=should-not-leak");
      },
    }),
  });
  t.after(() => api.close());

  const response = await api.inject({ method: "GET", url: "/v1/tenant-records" });
  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { error: { code: "SERVICE_UNAVAILABLE" } });
  assert.doesNotMatch(response.body, /password|should-not-leak/u);
});

test("certificate rejection and unavailable current state use bounded safe responses", async (t) => {
  let failure = new CertificateNotAcceptedError();
  const api = createTenantTrustApi({
    identityResolver: createIdentityResolver(),
    repository: createRepository({ async getProfile() { throw failure; } }),
  });
  t.after(() => api.close());

  const rejected = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(rejected.statusCode, 401);
  assert.deepEqual(rejected.json(), { error: { code: "CERTIFICATE_NOT_ACCEPTED" } });

  failure = new RequestStateUnavailableError();
  const unavailable = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(unavailable.statusCode, 503);
  assert.deepEqual(unavailable.json(), { error: { code: "SERVICE_UNAVAILABLE" } });
});

test("gateway adapter forwards only the raw socket and request headers", async () => {
  const socket = {};
  const headers = { "tenant-trust-gateway-version": "1" };
  let input;
  const authenticate = createGatewayRequestAuthenticator({
    async resolve(value) {
      input = value;
      return alphaAuthentication;
    },
  });

  const result = await authenticate({
    raw: { socket },
    headers,
    body: { tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac" },
    query: { tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac" },
  });
  assert.equal(result, alphaAuthentication);
  assert.deepEqual(input, { socket, headers });
});
