import assert from "node:assert/strict";
import test from "node:test";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import { GatewayIdentityError } from "@tenant-trust/gateway-identity";
import {
  AccessDeniedError,
  REQUEST_AUDIT_POLICY,
  REQUEST_STATE_POLICY,
  RequestAuditUnavailableError,
  createPostgresRequestAuditRecorder,
  createRequestAuditRecorder,
  createTenantTrustApi,
  hashAuditResourceIdentifier,
} from "../src/index.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const tenantId = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const subjectId = "sub_018f1234-5678-7abc-8def-0123456789ab";
const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: `sha256:${"a".repeat(64)}`,
  tenantId,
  subjectId,
});
const requestId = "req_018f1234-5678-7abc-8def-0123456789d1";
const correlationId = "cor_018f1234-5678-7abc-8def-0123456789e1";
const occurredAt = "2026-09-16T12:00:00.000Z";

function event(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    eventKind: "access",
    requestId,
    correlationId,
    tenantId,
    actorSubjectId: subjectId,
    authenticationSource: "mtls-certificate",
    action: "profile:read",
    resourceType: "tenant-profile",
    resourceIdHashSha256: hashAuditResourceIdentifier(subjectId),
    decision: "allow",
    reasonCode: "ACCESS_ALLOWED",
    method: "GET",
    routeTemplate: "/v1/profile",
    statusCode: 200,
    authorizationModeId: authorizationMode.modeId,
    operationId: null,
    occurredAt,
    ...overrides,
  };
}

function repository(overrides = {}) {
  return {
    authorizationMode,
    requestStatePolicy: REQUEST_STATE_POLICY,
    async getProfile() { return { tenantId, subjectId }; },
    async listRecords() { return []; },
    async getRecord(_authentication, recordId) { return { recordId }; },
    async exportRecords() {
      return {
        operation: { operationId: "op_018f1234-5678-4abc-8def-0123456789d2" },
        records: [],
      };
    },
    async reviewMembership() { return {}; },
    ...overrides,
  };
}

function createApi({ events = [], recorder, identityResolver, repositoryOverrides } = {}) {
  return createTenantTrustApi({
    identityResolver: identityResolver ?? { resolve: async () => authentication },
    repository: repository(repositoryOverrides),
    requestAuditRecorder: recorder ?? createRequestAuditRecorder({
      async write(value) { events.push(value); },
    }),
    requestIdFactory: () => requestId,
    correlationIdFactory: () => correlationId,
    clock: () => new Date(occurredAt),
  });
}

test("request audit policy is fail closed and excludes raw request data", () => {
  assert.deepEqual(REQUEST_AUDIT_POLICY, {
    schemaVersion: "1.0.0",
    mechanism: "append-only-request-outcomes-v1",
    correlationSource: "server-generated",
    failClosedOnCaptureFailure: true,
    rawHeadersCaptured: false,
    requestPayloadCaptured: false,
    responsePayloadCaptured: false,
    resourceIdentifiers: "sha256",
  });
});

test("request audit recorder accepts only fixed sanitized fields", async () => {
  const written = [];
  const recorder = createRequestAuditRecorder({ async write(value) { written.push(value); } });
  const accepted = await recorder.record(event());
  assert.equal(Object.isFrozen(accepted), true);
  assert.deepEqual(written, [accepted]);
  await assert.rejects(
    recorder.record({ ...event(), payload: { password: "must-not-enter-audit" } }),
    /fixed sanitized fields/u,
  );
});

test("PostgreSQL recorder uses one parameterized constrained writer call", async () => {
  const calls = [];
  const recorder = createPostgresRequestAuditRecorder({
    database: {
      async query(input) {
        calls.push(input);
        return { rowCount: 1, rows: [{ api_request_event_id: 1 }] };
      },
    },
  });
  await recorder.record(event());
  assert.equal(calls.length, 1);
  assert.match(calls[0].text, /audit\.record_api_request_event/u);
  assert.equal(calls[0].values.length, 17);
  assert.equal(JSON.stringify(calls).includes("must-not-enter-audit"), false);
});

test("API requires a branded fail-closed request audit recorder", () => {
  assert.throws(
    () => createTenantTrustApi({
      identityResolver: { resolve: async () => authentication },
      repository: repository(),
      requestAuditRecorder: { policy: REQUEST_AUDIT_POLICY, async record() {} },
    }),
    /branded fail-closed request audit recorder/u,
  );
});

test("successful requests capture correlated authentication and access outcomes", async (t) => {
  const events = [];
  const api = createApi({ events });
  t.after(() => api.close());
  const response = await api.inject({
    method: "GET",
    url: "/v1/profile",
    headers: {
      authorization: "Bearer secret-value",
      "x-request-id": "req_018f1234-5678-7abc-8def-0123456789ff",
      "x-correlation-id": "cor_018f1234-5678-7abc-8def-0123456789ff",
    },
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["x-request-id"], requestId);
  assert.equal(response.headers["x-correlation-id"], correlationId);
  assert.equal(events.length, 2);
  assert.deepEqual(events.map(({ eventKind, decision }) => [eventKind, decision]), [
    ["authentication", "allow"],
    ["access", "allow"],
  ]);
  assert.ok(events.every((value) => value.tenantId === tenantId));
  assert.ok(events.every((value) => value.actorSubjectId === subjectId));
  assert.ok(events.every((value) => value.action === "profile:read"));
  assert.ok(events.every((value) => value.resourceType === "tenant-profile"));
  assert.doesNotMatch(JSON.stringify(events), /secret-value|"headers"|"payload"|"body"|"cookie"/u);
});

test("access denials retain trusted actor and hashed resource without enumeration", async (t) => {
  const events = [];
  const recordId = "res_018f1234-5678-7abc-8def-0123456789b2";
  const api = createApi({
    events,
    repositoryOverrides: { async getRecord() { throw new AccessDeniedError(); } },
  });
  t.after(() => api.close());
  const response = await api.inject({ method: "GET", url: `/v1/tenant-records/${recordId}` });

  assert.equal(response.statusCode, 403);
  assert.equal(events.length, 2);
  assert.equal(events[1].eventKind, "access");
  assert.equal(events[1].decision, "deny");
  assert.equal(events[1].reasonCode, "ACCESS_DENIED");
  assert.equal(events[1].resourceIdHashSha256, hashAuditResourceIdentifier(recordId));
  assert.doesNotMatch(JSON.stringify(events), new RegExp(recordId, "u"));
});

test("failed authentication never trusts forged actor or tenant headers", async (t) => {
  const events = [];
  const api = createApi({
    events,
    identityResolver: {
      async resolve() { throw new GatewayIdentityError("FORWARDED_HEADER_INVALID"); },
    },
  });
  t.after(() => api.close());
  const forgedTenant = "tnt_018f1234-5678-7abc-8def-0123456789ac";
  const forgedSubject = "sub_018f1234-5678-7abc-8def-0123456789ad";
  const response = await api.inject({
    method: "GET",
    url: "/v1/tenant-records",
    headers: { "x-tenant-id": forgedTenant, "x-subject-id": forgedSubject },
  });

  assert.equal(response.statusCode, 401);
  assert.equal(events.length, 1);
  assert.equal(events[0].eventKind, "authentication");
  assert.equal(events[0].decision, "deny");
  assert.equal(events[0].tenantId, null);
  assert.equal(events[0].actorSubjectId, null);
  assert.doesNotMatch(JSON.stringify(events), new RegExp(`${forgedTenant}|${forgedSubject}`, "u"));
});

test("non-mTLS resolver output becomes a sanitized authentication denial", async (t) => {
  const events = [];
  const api = createApi({
    events,
    identityResolver: {
      async resolve() { return { ...authentication, source: "trusted-session" }; },
    },
  });
  t.after(() => api.close());
  const response = await api.inject({ method: "GET", url: "/v1/profile" });

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.json(), { error: { code: "CLIENT_CERTIFICATE_REQUIRED" } });
  assert.equal(events.length, 1);
  assert.equal(events[0].eventKind, "authentication");
  assert.equal(events[0].decision, "deny");
  assert.equal(events[0].tenantId, null);
  assert.equal(events[0].actorSubjectId, null);
});

test("audit capture failure blocks the repository and returns a safe unavailable response", async (t) => {
  let repositoryCalls = 0;
  const recorder = createRequestAuditRecorder({
    async write() { throw new Error("audit database password=must-not-leak"); },
  });
  const api = createApi({
    recorder,
    repositoryOverrides: {
      async getProfile() {
        repositoryCalls += 1;
        return {};
      },
    },
  });
  t.after(() => api.close());
  const response = await api.inject({ method: "GET", url: "/v1/profile" });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { error: { code: "SERVICE_UNAVAILABLE" } });
  assert.equal(repositoryCalls, 0);
  assert.doesNotMatch(response.body, /password|must-not-leak/u);
  await assert.rejects(recorder.record(event()), RequestAuditUnavailableError);
});
