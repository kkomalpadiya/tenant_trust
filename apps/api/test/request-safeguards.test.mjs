import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  IdempotencyConflictError,
  REQUEST_SAFEGUARD_POLICY,
  REQUEST_STATE_POLICY,
  UnsupportedSessionError,
  assertStatelessMtlsRequest,
  createRequestAuditRecorder,
  createTenantTrustApi,
  hashSensitiveIdempotencyKey,
  hashSensitiveRequest,
  normalizeSensitiveIdempotencyKey,
} from "../src/index.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const tenantId = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const subjectId = "sub_018f1234-5678-7abc-8def-0123456789ac";
const recordId = "res_018f1234-5678-7abc-8def-0123456789b0";
const idempotencyKey = "idem_018f1234-5678-4abc-8def-0123456789a1";
const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: "sha256:alpha-admin",
  tenantId,
  subjectId,
});

function repository(overrides = {}) {
  return {
    authorizationMode,
    requestSafeguardPolicy: REQUEST_SAFEGUARD_POLICY,
    requestStatePolicy: REQUEST_STATE_POLICY,
    async getProfile() { return {}; },
    async listRecords() { return []; },
    async getRecord() { return {}; },
    async exportRecords() {
      return {
        operation: { operationId: "op_018f1234-5678-4abc-8def-0123456789b2" },
        records: [],
      };
    },
    async reviewMembership() { return {}; },
    ...overrides,
  };
}

function createApi({ events = [], identityResolver, repositoryOverrides, requestTimeoutMilliseconds } = {}) {
  return createTenantTrustApi({
    identityResolver: identityResolver ?? { resolve: async () => authentication },
    repository: repository(repositoryOverrides),
    requestAuditRecorder: createRequestAuditRecorder({
      async write(event) { events.push(event); },
    }),
    requestTimeoutMilliseconds,
  });
}

test("request safeguard policy fixes stateless mTLS, size, timeout and replay boundaries", () => {
  assert.deepEqual(REQUEST_SAFEGUARD_POLICY, {
    schemaVersion: "1.0.0",
    mechanism: "stateless-mtls-replay-guard-v1",
    sessionMode: "stateless-mtls",
    ambientSessionCredentialsAccepted: false,
    sensitiveBodyLimitBytes: 4_096,
    maximumExportRecords: 25,
    requestTimeoutMilliseconds: 5_000,
    databaseStatementTimeoutMilliseconds: 4_000,
    databaseLockTimeoutMilliseconds: 1_000,
    idempotencyScope: "tenant-actor-action-key",
    idempotencyKeyStorage: "sha256",
  });
});

test("ambient cookie and bearer sessions are rejected before mTLS resolution", async (t) => {
  const events = [];
  let identityResolutions = 0;
  const api = createApi({
    events,
    identityResolver: { resolve: async () => {
      identityResolutions += 1;
      return authentication;
    } },
  });
  t.after(() => api.close());

  for (const headers of [{ authorization: "Bearer ignored" }, { cookie: "session=ignored" }]) {
    const response = await api.inject({ method: "GET", url: "/v1/profile", headers });
    assert.equal(response.statusCode, 401);
    assert.deepEqual(response.json(), { error: { code: "CLIENT_CERTIFICATE_REQUIRED" } });
    assert.equal(response.headers["cache-control"], "no-store");
  }
  assert.equal(identityResolutions, 0);
  assert.equal(events.length, 2);
  assert.ok(events.every((event) => event.reasonCode === "SESSION_CREDENTIAL_UNSUPPORTED"));
  assert.throws(() => assertStatelessMtlsRequest({ authorization: "Basic ignored" }), UnsupportedSessionError);
});

test("sensitive operations require an opaque idempotency header before authentication", async (t) => {
  let identityResolutions = 0;
  const api = createApi({
    identityResolver: { resolve: async () => {
      identityResolutions += 1;
      return authentication;
    } },
  });
  t.after(() => api.close());

  for (const headers of [undefined, { "idempotency-key": "predictable-key" }]) {
    const response = await api.inject({
      method: "POST",
      url: "/v1/tenant-records/export",
      headers,
      payload: { recordIds: [recordId] },
    });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: { code: "INVALID_REQUEST" } });
  }
  assert.equal(identityResolutions, 0);
});

test("a validated idempotency key and abort signal reach only the internal repository", async (t) => {
  let observed;
  const api = createApi({
    repositoryOverrides: {
      async exportRecords(resolvedAuthentication, recordIds, options) {
        observed = { resolvedAuthentication, recordIds, options };
        return {
          operation: { operationId: "op_018f1234-5678-4abc-8def-0123456789b2" },
          records: [],
        };
      },
    },
  });
  t.after(() => api.close());
  const response = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: { "idempotency-key": idempotencyKey },
    payload: { recordIds: [recordId] },
  });

  assert.equal(response.statusCode, 200);
  assert.equal(observed.resolvedAuthentication, authentication);
  assert.deepEqual(observed.recordIds, [recordId]);
  assert.equal(observed.options.idempotencyKey, idempotencyKey);
  assert.ok(observed.options.signal instanceof AbortSignal);
  assert.equal(observed.options.signal.aborted, false);
});

test("a protected request deadline aborts work and records one safe timeout denial", async (t) => {
  const events = [];
  let observedSignal;
  const api = createApi({
    events,
    requestTimeoutMilliseconds: 20,
    repositoryOverrides: {
      async getProfile(_authentication, { signal }) {
        observedSignal = signal;
        return new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
      },
    },
  });
  t.after(() => api.close());
  const response = await api.inject({ method: "GET", url: "/v1/profile" });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { error: { code: "SERVICE_UNAVAILABLE" } });
  assert.equal(observedSignal.aborted, true);
  assert.equal(events.at(-1).eventKind, "access");
  assert.equal(events.at(-1).decision, "deny");
  assert.equal(events.at(-1).reasonCode, "REQUEST_TIMEOUT");
});

test("conflicting sensitive replay returns one bounded conflict response", async (t) => {
  const events = [];
  const api = createApi({
    events,
    repositoryOverrides: {
      async exportRecords() { throw new IdempotencyConflictError(); },
    },
  });
  t.after(() => api.close());
  const response = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: { "idempotency-key": idempotencyKey },
    payload: { recordIds: [recordId] },
  });

  assert.equal(response.statusCode, 409);
  assert.deepEqual(response.json(), { error: { code: "IDEMPOTENCY_CONFLICT" } });
  assert.equal(events.at(-1).reasonCode, "IDEMPOTENCY_CONFLICT");
  assert.doesNotMatch(response.body, /tenant|subject|record|operation/u);
});

test("replay hashes are deterministic while raw keys and resources remain absent", () => {
  assert.equal(normalizeSensitiveIdempotencyKey(idempotencyKey), idempotencyKey);
  const keyHash = hashSensitiveIdempotencyKey(idempotencyKey);
  const requestHash = hashSensitiveRequest("record:export", [recordId]);
  assert.match(keyHash, /^[0-9a-f]{64}$/u);
  assert.match(requestHash, /^[0-9a-f]{64}$/u);
  assert.notEqual(keyHash, requestHash);
  assert.equal(hashSensitiveRequest("record:export", [recordId]), requestHash);
  assert.notEqual(hashSensitiveRequest("tenant:admin", [subjectId]), requestHash);
  assert.doesNotMatch(`${keyHash}${requestHash}`, new RegExp(`${idempotencyKey}|${recordId}`, "u"));
});
