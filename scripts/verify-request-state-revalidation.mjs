import assert from "node:assert/strict";
import { Pool } from "pg";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  REQUEST_STATE_POLICY,
  createPostgresTenantRepository,
  createTenantTrustApi,
} from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";
import { createVerificationRequestAuditRecorder } from "./lib/request-audit-fixtures.mjs";
import { createLiveRequestStateFixture } from "./lib/request-state-fixtures.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
assert.equal(REQUEST_STATE_POLICY.maximumStateAgeSeconds, 5);
assert.equal(REQUEST_STATE_POLICY.crossRequestAllowCache, false);
assert.equal(REQUEST_STATE_POLICY.revalidation, "every-protected-request");

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 1,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 1_000,
});

let fixture;
let api;
let tenantSnapshot;
let membershipSnapshot;
try {
  fixture = await createLiveRequestStateFixture(pool);
  const identity = fixture.identities.alphaMember;
  const tenant = await pool.query(
    "SELECT state::text, version, updated_at::text FROM identity.tenants WHERE tenant_id = $1",
    [identity.tenantId],
  );
  const membership = await pool.query(
    `SELECT state::text, version, updated_at::text
     FROM identity.tenant_memberships
     WHERE tenant_id = $1 AND subject_id = $2`,
    [identity.tenantId, identity.subjectId],
  );
  assert.equal(tenant.rowCount, 1);
  assert.equal(membership.rowCount, 1);
  tenantSnapshot = tenant.rows[0];
  membershipSnapshot = membership.rows[0];

  let identityResolutions = 0;
  api = createTenantTrustApi({
    identityResolver: {
      resolve: async () => {
        identityResolutions += 1;
        return identity;
      },
    },
    repository: createPostgresTenantRepository({ pool, authorizationMode }),
    requestAuditRecorder: createVerificationRequestAuditRecorder(),
  });

  const backendBefore = await pool.query("SELECT pg_backend_pid() AS pid");
  const baseline = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(baseline.statusCode, 200);

  await pool.query(
    `UPDATE identity.tenant_memberships
     SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
     WHERE tenant_id = $1 AND subject_id = $2`,
    [identity.tenantId, identity.subjectId],
  );
  const suspendedMembership = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(suspendedMembership.statusCode, 403);
  assert.deepEqual(suspendedMembership.json(), { error: { code: "ACCESS_DENIED" } });
  await pool.query(
    `UPDATE identity.tenant_memberships
     SET state = $3::identity.membership_state, version = $4, updated_at = $5::timestamptz
     WHERE tenant_id = $1 AND subject_id = $2`,
    [identity.tenantId, identity.subjectId, membershipSnapshot.state, membershipSnapshot.version, membershipSnapshot.updated_at],
  );
  assert.equal((await api.inject({ method: "GET", url: "/v1/profile" })).statusCode, 200);

  await pool.query(
    `UPDATE identity.tenants
     SET state = 'suspended', version = version + 1, updated_at = clock_timestamp()
     WHERE tenant_id = $1`,
    [identity.tenantId],
  );
  const suspendedTenant = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(suspendedTenant.statusCode, 403);
  assert.deepEqual(suspendedTenant.json(), { error: { code: "ACCESS_DENIED" } });
  await pool.query(
    `UPDATE identity.tenants
     SET state = $2::identity.tenant_state, version = $3, updated_at = $4::timestamptz
     WHERE tenant_id = $1`,
    [identity.tenantId, tenantSnapshot.state, tenantSnapshot.version, tenantSnapshot.updated_at],
  );
  assert.equal((await api.inject({ method: "GET", url: "/v1/profile" })).statusCode, 200);

  await pool.query(
    `UPDATE identity.certificates
     SET state = 'revoked', version = version + 1,
         state_changed_at = clock_timestamp(), updated_at = clock_timestamp()
     WHERE tenant_id = $1 AND certificate_id = $2`,
    [identity.tenantId, fixture.certificateIds.alphaMember],
  );
  const revoked = await api.inject({ method: "GET", url: "/v1/profile" });
  assert.equal(revoked.statusCode, 401);
  assert.deepEqual(revoked.json(), { error: { code: "CERTIFICATE_NOT_ACCEPTED" } });

  const backendAfter = await pool.query("SELECT pg_backend_pid() AS pid");
  assert.equal(backendAfter.rows[0].pid, backendBefore.rows[0].pid);
  assert.equal(identityResolutions, 6);

  console.log("PASS the same authenticated session rechecks certificate, tenant and membership state on every request");
  console.log("PASS revoked certificates return 401 while suspended tenant or membership state returns uniform 403 denial");
  console.log("PASS one reused PostgreSQL connection applies the five-second no-cache request-state boundary");
} finally {
  if (api) await api.close();
  if (tenantSnapshot && fixture) {
    await pool.query(
      `UPDATE identity.tenants
       SET state = $2::identity.tenant_state, version = $3, updated_at = $4::timestamptz
       WHERE tenant_id = $1`,
      [fixture.identities.alphaMember.tenantId, tenantSnapshot.state, tenantSnapshot.version, tenantSnapshot.updated_at],
    );
  }
  if (membershipSnapshot && fixture) {
    await pool.query(
      `UPDATE identity.tenant_memberships
       SET state = $3::identity.membership_state, version = $4, updated_at = $5::timestamptz
       WHERE tenant_id = $1 AND subject_id = $2`,
      [
        fixture.identities.alphaMember.tenantId,
        fixture.identities.alphaMember.subjectId,
        membershipSnapshot.state,
        membershipSnapshot.version,
        membershipSnapshot.updated_at,
      ],
    );
  }
  if (fixture) await fixture.cleanup();
  await pool.end();
}
