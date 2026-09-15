import assert from "node:assert/strict";
import { Pool } from "pg";
import {
  AUTHORIZATION_MODE_IDS,
  AuthorizationError,
  selectAuthorizationMode,
} from "@tenant-trust/authorization";
import { createPostgresTenantRepository, createTenantTrustApi } from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
assert.deepEqual(authorizationMode, {
  modeId: "pki-rbac-baseline-v1",
  certificatePolicy: "tenant-scoped-x509",
  rolePolicy: "role-action-matrix-v1",
  adaptiveTrustUsed: false,
});
assert.throws(
  () => selectAuthorizationMode("adaptive-trust-v1"),
  (error) => error instanceof AuthorizationError
    && error.reasonCode === "AUTHORIZATION_MODE_UNSUPPORTED",
);

const identities = Object.freeze({
  alphaMember: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:alpha-member-baseline-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  }),
  alphaAdmin: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:alpha-admin-baseline-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
  }),
  betaMember: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:beta-member-baseline-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
  }),
});

const records = Object.freeze({
  alphaMember: "res_018f1234-5678-7abc-8def-0123456789b0",
  alphaAdmin: "res_018f1234-5678-7abc-8def-0123456789b1",
  betaMember: "res_018f1234-5678-7abc-8def-0123456789b2",
});

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 1_000,
});

assert.throws(
  () => createPostgresTenantRepository({ pool }),
  /explicit supported authorization mode/u,
);

let currentIdentity = identities.alphaMember;
let identityResolutions = 0;
const sensitiveDecisions = [];
const repository = createPostgresTenantRepository({
  pool,
  authorizationMode,
  sensitiveOperationAuthorizer: async (request) => {
    sensitiveDecisions.push(request.authorization);
    assert.equal(request.authorization.modeId, authorizationMode.modeId);
    assert.equal(request.authorization.adaptiveTrustUsed, false);
    assert.equal(request.authorization.outcome, "requires-controls");
    assert.equal("trustScore" in request.authorization, false);
    assert.equal("evidence" in request.authorization, false);
    return true;
  },
});
const api = createTenantTrustApi({
  identityResolver: {
    resolve: async () => {
      identityResolutions += 1;
      return currentIdentity;
    },
  },
  repository,
});

async function request(identity, options) {
  currentIdentity = identity;
  return api.inject(options);
}

let defaultDenyApi;
try {
  const profile = await request(identities.alphaMember, { method: "GET", url: "/v1/profile" });
  assert.equal(profile.statusCode, 200);
  assert.equal(profile.json().profile.tenantId, identities.alphaMember.tenantId);

  const memberRecords = await request(identities.alphaMember, { method: "GET", url: "/v1/tenant-records" });
  assert.equal(memberRecords.statusCode, 200);
  assert.deepEqual(memberRecords.json().records.map(({ recordId }) => recordId), [records.alphaMember]);

  const adminRecords = await request(identities.alphaAdmin, { method: "GET", url: "/v1/tenant-records" });
  assert.equal(adminRecords.statusCode, 200);
  assert.deepEqual(
    adminRecords.json().records.map(({ recordId }) => recordId),
    [records.alphaMember, records.alphaAdmin],
  );

  const resolutionCount = identityResolutions;
  const callerSelectedMode = await request(identities.alphaAdmin, {
    method: "GET",
    url: "/v1/profile?authorizationMode=adaptive-trust-v1",
  });
  assert.equal(callerSelectedMode.statusCode, 400);
  assert.equal(identityResolutions, resolutionCount);

  const memberExport = await request(identities.alphaMember, {
    method: "POST",
    url: "/v1/tenant-records/export",
    payload: { recordIds: [records.alphaMember] },
  });
  assert.equal(memberExport.statusCode, 403);
  assert.equal(sensitiveDecisions.length, 0);

  const adminExport = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/tenant-records/export",
    payload: { recordIds: [records.alphaMember, records.alphaAdmin] },
  });
  assert.equal(adminExport.statusCode, 200);
  assert.equal(adminExport.json().operation.authorizationModeId, authorizationMode.modeId);
  assert.equal(sensitiveDecisions.length, 1);

  const betaRecords = await request(identities.betaMember, {
    method: "GET",
    url: "/v1/tenant-records",
    headers: {
      "x-tenant-id": identities.alphaMember.tenantId,
      "x-subject-id": identities.alphaMember.subjectId,
    },
  });
  assert.equal(betaRecords.statusCode, 200);
  assert.deepEqual(betaRecords.json().records.map(({ recordId }) => recordId), [records.betaMember]);

  const sessionAttempt = await request(
    { ...identities.alphaMember, source: "trusted-session" },
    { method: "GET", url: "/v1/profile" },
  );
  assert.equal(sessionAttempt.statusCode, 403);
  assert.deepEqual(sessionAttempt.json(), { error: { code: "ACCESS_DENIED" } });

  defaultDenyApi = createTenantTrustApi({
    identityResolver: { resolve: async () => identities.alphaAdmin },
    repository: createPostgresTenantRepository({ pool, authorizationMode }),
  });
  const missingControls = await defaultDenyApi.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    payload: { recordIds: [records.alphaMember] },
  });
  assert.equal(missingControls.statusCode, 403);

  console.log("PASS explicit PKI plus RBAC mode uses tenant-scoped certificate identity and the role matrix");
  console.log("PASS member, administrator and tenant resource scopes remain enforced without adaptive trust inputs");
  console.log("PASS callers cannot select modes and sensitive operations still fail closed without additional controls");
} finally {
  if (defaultDenyApi) await defaultDenyApi.close();
  await api.close();
  await pool.end();
}
