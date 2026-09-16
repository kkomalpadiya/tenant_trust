import assert from "node:assert/strict";
import { Pool } from "pg";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import { GatewayIdentityError } from "@tenant-trust/gateway-identity";
import {
  createPostgresRequestAuditRecorder,
  createPostgresTenantRepository,
  createTenantTrustApi,
  hashAuditResourceIdentifier,
} from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";
import { createLiveRequestStateFixture } from "./lib/request-state-fixtures.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const alphaRecord = "res_018f1234-5678-7abc-8def-0123456789b0";
const betaRecord = "res_018f1234-5678-7abc-8def-0123456789b2";
const forgedRequestId = "req_018f1234-5678-7abc-8def-0123456789ff";
const forgedCorrelationId = "cor_018f1234-5678-7abc-8def-0123456789ff";

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 3,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 1_000,
});
const auditClient = await pool.connect();
await auditClient.query("BEGIN");
const fixture = await createLiveRequestStateFixture(pool);
const { identities } = fixture;

let currentIdentity = identities.alphaMember;
const api = createTenantTrustApi({
  identityResolver: {
    async resolve() {
      if (!currentIdentity) throw new GatewayIdentityError("PEER_CERTIFICATE_MISSING");
      return currentIdentity;
    },
  },
  repository: createPostgresTenantRepository({
    pool,
    authorizationMode,
    sensitiveOperationAuthorizer: async ({ context }) => context.roles.includes("tenant-admin"),
  }),
  requestAuditRecorder: createPostgresRequestAuditRecorder({ database: auditClient }),
});

const requests = [];
async function request(identity, options) {
  currentIdentity = identity;
  const response = await api.inject(options);
  requests.push(Object.freeze({
    requestId: response.headers["x-request-id"],
    correlationId: response.headers["x-correlation-id"],
    statusCode: response.statusCode,
  }));
  return response;
}

try {
  const profile = await request(identities.alphaMember, { method: "GET", url: "/v1/profile" });
  assert.equal(profile.statusCode, 200);

  const foreignRecord = await request(identities.alphaMember, {
    method: "GET",
    url: `/v1/tenant-records/${betaRecord}`,
  });
  assert.equal(foreignRecord.statusCode, 403);

  const missingCertificate = await request(null, { method: "GET", url: "/v1/tenant-records" });
  assert.equal(missingCertificate.statusCode, 401);

  const exportResponse = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: {
      authorization: "Bearer audit-secret-must-not-appear",
      cookie: "session=audit-secret-must-not-appear",
      "x-request-id": forgedRequestId,
      "x-correlation-id": forgedCorrelationId,
      "x-tenant-id": identities.betaMember.tenantId,
      "x-subject-id": identities.betaMember.subjectId,
    },
    payload: { recordIds: [alphaRecord] },
  });
  assert.equal(exportResponse.statusCode, 200);

  for (const metadata of requests) {
    assert.match(metadata.requestId, /^req_[0-9a-f-]{36}$/u);
    assert.match(metadata.correlationId, /^cor_[0-9a-f-]{36}$/u);
  }
  assert.notEqual(requests[3].requestId, forgedRequestId);
  assert.notEqual(requests[3].correlationId, forgedCorrelationId);

  const result = await auditClient.query(
    `SELECT *
     FROM audit.api_request_events
     WHERE request_id = ANY($1::text[])
     ORDER BY api_request_event_id`,
    [requests.map(({ requestId }) => requestId)],
  );
  assert.equal(result.rowCount, 7);

  for (const metadata of requests) {
    const events = result.rows.filter((row) => row.request_id === metadata.requestId);
    assert.equal(events.length, metadata.statusCode === 401 ? 1 : 2);
    assert.ok(events.every((row) => row.correlation_id === metadata.correlationId));
  }

  const profileAccess = result.rows.find((row) => (
    row.request_id === requests[0].requestId && row.event_kind === "access"
  ));
  assert.equal(profileAccess.tenant_id, identities.alphaMember.tenantId);
  assert.equal(profileAccess.actor_subject_id, identities.alphaMember.subjectId);
  assert.equal(profileAccess.action, "profile:read");
  assert.equal(profileAccess.resource_type, "tenant-profile");
  assert.equal(profileAccess.decision, "allow");

  const deniedAccess = result.rows.find((row) => (
    row.request_id === requests[1].requestId && row.event_kind === "access"
  ));
  assert.equal(deniedAccess.tenant_id, identities.alphaMember.tenantId);
  assert.equal(deniedAccess.actor_subject_id, identities.alphaMember.subjectId);
  assert.equal(deniedAccess.decision, "deny");
  assert.equal(deniedAccess.reason_code, "ACCESS_DENIED");
  assert.equal(deniedAccess.resource_id_hash_sha256, hashAuditResourceIdentifier(betaRecord));

  const failedAuthentication = result.rows.find((row) => row.request_id === requests[2].requestId);
  assert.equal(failedAuthentication.event_kind, "authentication");
  assert.equal(failedAuthentication.tenant_id, null);
  assert.equal(failedAuthentication.actor_subject_id, null);
  assert.equal(failedAuthentication.decision, "deny");
  assert.equal(failedAuthentication.reason_code, "CLIENT_CERTIFICATE_REQUIRED");

  const exportAccess = result.rows.find((row) => (
    row.request_id === requests[3].requestId && row.event_kind === "access"
  ));
  assert.equal(exportAccess.tenant_id, identities.alphaAdmin.tenantId);
  assert.equal(exportAccess.actor_subject_id, identities.alphaAdmin.subjectId);
  assert.equal(exportAccess.action, "record:export");
  assert.equal(exportAccess.resource_id_hash_sha256, hashAuditResourceIdentifier(alphaRecord));
  assert.equal(exportAccess.operation_id, exportResponse.json().operation.operationId);
  assert.equal(exportAccess.authorization_mode_id, authorizationMode.modeId);

  const serializedRows = JSON.stringify(result.rows);
  assert.doesNotMatch(serializedRows, /audit-secret-must-not-appear/u);
  assert.doesNotMatch(serializedRows, new RegExp(betaRecord, "u"));
  assert.doesNotMatch(serializedRows, new RegExp(forgedRequestId, "u"));
  assert.doesNotMatch(serializedRows, new RegExp(forgedCorrelationId, "u"));

  console.log("PASS durable authentication and access outcomes retain trusted actor, tenant, action, resource hash and decision");
  console.log("PASS server-generated request, correlation and operation IDs join each request without trusting caller headers");
  console.log("PASS append-only audit rows exclude raw headers, secrets, resource identifiers and request or response payloads");
} finally {
  await api.close();
  await auditClient.query("ROLLBACK");
  auditClient.release();
  await fixture.cleanup();
  await pool.end();
}
