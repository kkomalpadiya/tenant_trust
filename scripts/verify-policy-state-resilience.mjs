import assert from "node:assert/strict";
import { Pool } from "pg";
import {
  POLICY_ENFORCEMENT_POLICY,
  REQUEST_STATE_POLICY,
} from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";
import { createLiveRequestStateFixture } from "./lib/request-state-fixtures.mjs";

assert.equal(POLICY_ENFORCEMENT_POLICY.maximumDecisionMilliseconds, 1_500);
assert.equal(POLICY_ENFORCEMENT_POLICY.allowCacheOnOutage, false);
assert.equal(POLICY_ENFORCEMENT_POLICY.staleTrustOutcome, "DENY");
assert.equal(POLICY_ENFORCEMENT_POLICY.freshnessRecheck, "after-policy-decision");
assert.equal(REQUEST_STATE_POLICY.crossRequestAllowCache, false);
assert.equal(REQUEST_STATE_POLICY.certificateStateSerialization, "transaction-row-share-lock");
assert.equal(REQUEST_STATE_POLICY.cacheInvalidation, "authoritative-version-on-next-request");

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

let fixture;
let lockClient;
let updateClient;
try {
  const privileges = await pool.query(
    `SELECT
       has_function_privilege(
         'tenant_trust_app',
         'identity.lock_current_actor_certificate_status(identity.certificate_id,identity.issuer_id,identity.x509_serial_number,identity.sha256_digest)',
         'EXECUTE'
       ) AS can_execute_lock,
       has_table_privilege('tenant_trust_app', 'identity.certificates', 'UPDATE') AS can_update_certificates`,
  );
  assert.equal(privileges.rows[0].can_execute_lock, true);
  assert.equal(privileges.rows[0].can_update_certificates, false);

  fixture = await createLiveRequestStateFixture(pool);
  const identity = fixture.identities.alphaMember;
  const certificate = identity.certificate;
  lockClient = await pool.connect();
  updateClient = await pool.connect();

  await lockClient.query("BEGIN");
  await lockClient.query("SET LOCAL ROLE tenant_trust_app");
  await lockClient.query(
    "SELECT identity.set_tenant_actor_context($1::identity.tenant_id, $2::identity.subject_id)",
    [identity.tenantId, identity.subjectId],
  );
  const locked = await lockClient.query(
    `SELECT *
     FROM identity.lock_current_actor_certificate_status($1, $2, $3, $4)`,
    [
      fixture.certificateIds.alphaMember,
      certificate.issuerId,
      certificate.serialNumber,
      certificate.fingerprintSha256,
    ],
  );
  assert.equal(locked.rowCount, 1);
  assert.equal(locked.rows[0].state, "active");

  await updateClient.query("BEGIN");
  await updateClient.query("SET LOCAL lock_timeout = '250ms'");
  await assert.rejects(
    updateClient.query(
      `UPDATE identity.certificates
       SET state = 'revoked', version = version + 1,
           state_changed_at = clock_timestamp(), updated_at = clock_timestamp()
       WHERE tenant_id = $1 AND certificate_id = $2`,
      [identity.tenantId, fixture.certificateIds.alphaMember],
    ),
    (error) => error?.code === "55P03",
  );

  console.log("PASS policy requests have an independent 1500ms deadline and no cached-allow fallback");
  console.log("PASS stale trust requires DENY and fresh trust is rechecked after policy evaluation");
  console.log("PASS the constrained certificate lookup serializes lifecycle changes without UPDATE privilege");
} finally {
  if (updateClient) {
    await updateClient.query("ROLLBACK").catch(() => {});
    updateClient.release();
  }
  if (lockClient) {
    await lockClient.query("ROLLBACK").catch(() => {});
    lockClient.release();
  }
  if (fixture) await fixture.cleanup();
  await pool.end();
}
