import assert from "node:assert/strict";
import { Pool } from "pg";
import { resolveRoleAction } from "@tenant-trust/authorization";
import { createPostgresTenantRepository, createTenantTrustApi } from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";

const identities = Object.freeze({
  alphaMember: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:alpha-member-sensitive-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  }),
  alphaAdmin: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:alpha-admin-sensitive-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
  }),
  betaMember: Object.freeze({
    source: "mtls-certificate",
    authenticationId: "sha256:beta-member-sensitive-verification",
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac",
    subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
  }),
});

const records = Object.freeze({
  alphaMember: "res_018f1234-5678-7abc-8def-0123456789b0",
  alphaAdmin: "res_018f1234-5678-7abc-8def-0123456789b1",
  betaMember: "res_018f1234-5678-7abc-8def-0123456789b2",
});

const operationIds = [];
async function verificationControlAuthorizer(request) {
  assert.equal(request.context.authentication.source, "mtls-certificate");
  assert.deepEqual(request.context.roles, ["tenant-admin"]);
  assert.equal(resolveRoleAction(request.context, request.action), request.eligibility);
  assert.equal(request.eligibility.disposition, "requires-controls");
  assert.match(request.operationId, /^op_[0-9a-f-]{36}$/u);
  operationIds.push(request.operationId);
  return true;
}

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
  repository: createPostgresTenantRepository({
    pool,
    sensitiveOperationAuthorizer: verificationControlAuthorizer,
  }),
});

async function request(identity, options) {
  currentIdentity = identity;
  return api.inject(options);
}

try {
  const memberExport = await request(identities.alphaMember, {
    method: "POST",
    url: "/v1/tenant-records/export",
    payload: { recordIds: [records.alphaMember] },
  });
  assert.equal(memberExport.statusCode, 403);
  assert.deepEqual(memberExport.json(), { error: { code: "ACCESS_DENIED" } });
  assert.equal(operationIds.length, 0);

  const alphaExport = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: {
      "x-tenant-id": identities.betaMember.tenantId,
      "x-subject-id": identities.betaMember.subjectId,
    },
    payload: { recordIds: [records.alphaMember, records.alphaAdmin] },
  });
  assert.equal(alphaExport.statusCode, 200);
  assert.equal(alphaExport.json().operation.tenantId, identities.alphaAdmin.tenantId);
  assert.equal(alphaExport.json().operation.requestedBy, identities.alphaAdmin.subjectId);
  assert.equal(alphaExport.json().operation.action, "record:export");
  assert.equal(alphaExport.json().operation.recordCount, 2);
  assert.deepEqual(
    alphaExport.json().records.map(({ recordId }) => recordId),
    [records.alphaMember, records.alphaAdmin],
  );

  const foreignExport = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/tenant-records/export",
    payload: { recordIds: [records.alphaMember, records.betaMember] },
  });
  const absentExport = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/tenant-records/export",
    payload: { recordIds: [records.alphaMember, "res_018f1234-5678-7abc-8def-0123456789bf"] },
  });
  assert.equal(foreignExport.statusCode, 403);
  assert.deepEqual(foreignExport.json(), absentExport.json());

  const memberReview = await request(identities.alphaMember, {
    method: "POST",
    url: "/v1/admin/membership-reviews",
    payload: { subjectId: identities.alphaMember.subjectId },
  });
  assert.equal(memberReview.statusCode, 403);

  const alphaReview = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/admin/membership-reviews",
    payload: { subjectId: identities.alphaMember.subjectId },
  });
  assert.equal(alphaReview.statusCode, 200);
  assert.equal(alphaReview.json().operation.tenantId, identities.alphaAdmin.tenantId);
  assert.equal(alphaReview.json().operation.targetSubjectId, identities.alphaMember.subjectId);
  assert.deepEqual(alphaReview.json().membership.roles, ["tenant-member"]);

  const foreignReview = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/admin/membership-reviews",
    payload: { subjectId: identities.betaMember.subjectId },
  });
  assert.equal(foreignReview.statusCode, 403);
  assert.deepEqual(foreignReview.json(), { error: { code: "ACCESS_DENIED" } });

  const injectedTenant = await request(identities.alphaAdmin, {
    method: "POST",
    url: "/v1/admin/membership-reviews?tenantId=tnt_other",
    payload: { subjectId: identities.alphaMember.subjectId },
  });
  assert.equal(injectedTenant.statusCode, 400);

  assert.equal(operationIds.length, 5);
  assert.equal(new Set(operationIds).size, operationIds.length);
  assert.equal(alphaExport.json().operation.operationId, operationIds[0]);
  assert.equal(alphaReview.json().operation.operationId, operationIds[3]);

  console.log("PASS sensitive export is tenant-admin-only, bounded, all-or-nothing and tenant-scoped");
  console.log("PASS membership review rejects members, foreign subjects and caller-selected tenant controls");
  console.log("PASS successful sensitive operations expose unique server-generated operation IDs for later audit capture");
} finally {
  await api.close();
  await pool.end();
}
