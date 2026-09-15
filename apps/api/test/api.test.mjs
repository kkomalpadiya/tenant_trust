import assert from "node:assert/strict";
import test from "node:test";
import { GatewayIdentityError } from "@tenant-trust/gateway-identity";
import {
  AccessDeniedError,
  createGatewayRequestAuthenticator,
  createTenantTrustApi,
} from "../src/index.mjs";

const alphaAuthentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: "sha256:alpha",
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
});

function createRepository(overrides = {}) {
  return {
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
