import assert from "node:assert/strict";
import { Pool } from "pg";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import { createTenantTrustApi, createPostgresTenantRepository } from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";

const identities = Object.freeze({
  alphaMember: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:alpha-member-api-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  }),
  alphaAdmin: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:alpha-admin-api-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
  }),
  betaMember: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:beta-member-api-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
  }),
});
const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);

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

let currentIdentity = identities.alphaMember;
const api = createTenantTrustApi({
  identityResolver: { resolve: async () => currentIdentity },
  repository: createPostgresTenantRepository({ pool, authorizationMode }),
});

async function request(identity, options) {
  currentIdentity = identity;
  return api.inject(options);
}

try {
  const profile = await request(identities.alphaMember, { method: "GET", url: "/v1/profile" });
  assert.equal(profile.statusCode, 200);
  assert.equal(profile.json().profile.tenantId, identities.alphaMember.tenantId);
  assert.equal(profile.json().profile.subjectId, identities.alphaMember.subjectId);
  assert.deepEqual(profile.json().profile.roles, ["tenant-member"]);

  const alphaMemberRecords = await request(identities.alphaMember, {
    method: "GET",
    url: "/v1/tenant-records",
    headers: {
      "x-tenant-id": identities.betaMember.tenantId,
      "x-subject-id": identities.betaMember.subjectId,
      "tenant-trust-client-verification": "SUCCESS",
    },
  });
  assert.equal(alphaMemberRecords.statusCode, 200);
  assert.deepEqual(
    alphaMemberRecords.json().records.map((record) => record.recordId),
    ["res_018f1234-5678-7abc-8def-0123456789b0"],
  );

  const ownRecord = await request(identities.alphaMember, {
    method: "GET",
    url: "/v1/tenant-records/res_018f1234-5678-7abc-8def-0123456789b0",
  });
  assert.equal(ownRecord.statusCode, 200);
  assert.equal(ownRecord.json().record.ownerSubjectId, identities.alphaMember.subjectId);

  const sameTenantOtherOwner = await request(identities.alphaMember, {
    method: "GET",
    url: "/v1/tenant-records/res_018f1234-5678-7abc-8def-0123456789b1",
  });
  const foreignTenant = await request(identities.alphaMember, {
    method: "GET",
    url: "/v1/tenant-records/res_018f1234-5678-7abc-8def-0123456789b2",
  });
  assert.equal(sameTenantOtherOwner.statusCode, 403);
  assert.equal(foreignTenant.statusCode, 403);
  assert.deepEqual(sameTenantOtherOwner.json(), foreignTenant.json());

  const alphaAdminRecords = await request(identities.alphaAdmin, {
    method: "GET",
    url: "/v1/tenant-records",
  });
  assert.equal(alphaAdminRecords.statusCode, 200);
  assert.deepEqual(
    alphaAdminRecords.json().records.map((record) => record.recordId),
    [
      "res_018f1234-5678-7abc-8def-0123456789b0",
      "res_018f1234-5678-7abc-8def-0123456789b1",
    ],
  );

  const betaRecords = await request(identities.betaMember, {
    method: "GET",
    url: "/v1/tenant-records",
  });
  assert.equal(betaRecords.statusCode, 200);
  assert.deepEqual(
    betaRecords.json().records.map((record) => record.recordId),
    ["res_018f1234-5678-7abc-8def-0123456789b2"],
  );

  console.log("PASS certificate-authenticated profile and tenant-record APIs preserve actor ownership and tenant isolation");
  console.log("PASS forged identity headers cannot select API tenant context and guessed records return a uniform denial");
} finally {
  await api.close();
  await pool.end();
}
