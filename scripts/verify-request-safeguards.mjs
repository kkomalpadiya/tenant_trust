import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { AUTHORIZATION_MODE_IDS, selectAuthorizationMode } from "@tenant-trust/authorization";
import {
  createPostgresTenantRepository,
  createTenantTrustApi,
  hashSensitiveIdempotencyKey,
} from "@tenant-trust/api";
import { environment } from "./lib/foundation-context.mjs";
import { createVerificationRequestAuditRecorder } from "./lib/request-audit-fixtures.mjs";
import { createLiveRequestStateFixture } from "./lib/request-state-fixtures.mjs";

const authorizationMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);
const records = Object.freeze({
  alphaMember: "res_018f1234-5678-7abc-8def-0123456789b0",
  alphaAdmin: "res_018f1234-5678-7abc-8def-0123456789b1",
});
const replayKey = `idem_${randomUUID()}`;
const timeoutKey = `idem_${randomUUID()}`;
const receiptKeyHashes = [replayKey, timeoutKey].map(hashSensitiveIdempotencyKey);

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 4,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 1_000,
});
const fixture = await createLiveRequestStateFixture(pool);
const { identities } = fixture;
let identityResolutions = 0;
const events = [];
const api = createTenantTrustApi({
  identityResolver: { resolve: async () => {
    identityResolutions += 1;
    return identities.alphaAdmin;
  } },
  repository: createPostgresTenantRepository({
    pool,
    authorizationMode,
    sensitiveOperationAuthorizer: async () => true,
  }),
  requestAuditRecorder: createVerificationRequestAuditRecorder(events),
});

const timeoutEvents = [];
const timeoutApi = createTenantTrustApi({
  identityResolver: { resolve: async () => identities.alphaAdmin },
  repository: createPostgresTenantRepository({
    pool,
    authorizationMode,
    sensitiveOperationAuthorizer: async ({ signal }) => new Promise((_resolve, reject) => {
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    }),
  }),
  requestAuditRecorder: createVerificationRequestAuditRecorder(timeoutEvents),
  requestTimeoutMilliseconds: 50,
});

async function waitForRolledBackReceipt(keyHash) {
  for (let attempt = 0; attempt < 25; attempt += 1) {
    const result = await pool.query(
      "SELECT count(*)::int AS count FROM audit.api_sensitive_operation_receipts WHERE idempotency_key_hash_sha256 = $1",
      [keyHash],
    );
    if (result.rows[0].count === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("Timed-out sensitive operation retained a replay receipt.");
}

try {
  const first = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: { "idempotency-key": replayKey },
    payload: { recordIds: [records.alphaMember] },
  });
  assert.equal(first.statusCode, 200);
  assert.equal(first.json().operation.idempotentReplay, false);

  const replay = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: { "idempotency-key": replayKey },
    payload: { recordIds: [records.alphaMember] },
  });
  assert.equal(replay.statusCode, 200);
  assert.equal(replay.json().operation.idempotentReplay, true);
  assert.equal(replay.json().operation.operationId, first.json().operation.operationId);

  const conflict = await api.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: { "idempotency-key": replayKey },
    payload: { recordIds: [records.alphaAdmin] },
  });
  assert.equal(conflict.statusCode, 409);
  assert.deepEqual(conflict.json(), { error: { code: "IDEMPOTENCY_CONFLICT" } });

  const receipt = await pool.query(
    `SELECT operation_id, idempotency_key_hash_sha256, request_hash_sha256
     FROM audit.api_sensitive_operation_receipts
     WHERE idempotency_key_hash_sha256 = $1`,
    [receiptKeyHashes[0]],
  );
  assert.equal(receipt.rowCount, 1);
  assert.equal(receipt.rows[0].operation_id, first.json().operation.operationId);
  assert.match(receipt.rows[0].request_hash_sha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(JSON.stringify(receipt.rows), new RegExp(`${replayKey}|${records.alphaMember}`, "u"));

  const resolutionsBeforeSessionAttempt = identityResolutions;
  const sessionAttempt = await api.inject({
    method: "GET",
    url: "/v1/profile",
    headers: { cookie: "session=must-not-be-accepted" },
  });
  assert.equal(sessionAttempt.statusCode, 401);
  assert.equal(identityResolutions, resolutionsBeforeSessionAttempt);
  assert.equal(sessionAttempt.headers["cache-control"], "no-store");

  const oversized = await api.inject({
    method: "POST",
    url: "/v1/admin/membership-reviews",
    headers: { "content-type": "application/json", "idempotency-key": `idem_${randomUUID()}` },
    payload: JSON.stringify({ subjectId: identities.alphaMember.subjectId, padding: "x".repeat(4_096) }),
  });
  assert.equal(oversized.statusCode, 413);

  const timedOut = await timeoutApi.inject({
    method: "POST",
    url: "/v1/tenant-records/export",
    headers: { "idempotency-key": timeoutKey },
    payload: { recordIds: [records.alphaMember] },
  });
  assert.equal(timedOut.statusCode, 503);
  assert.deepEqual(timedOut.json(), { error: { code: "SERVICE_UNAVAILABLE" } });
  assert.equal(timeoutEvents.at(-1).reasonCode, "REQUEST_TIMEOUT");
  await waitForRolledBackReceipt(receiptKeyHashes[1]);

  assert.equal(events.filter((event) => event.reasonCode === "IDEMPOTENCY_CONFLICT").length, 1);
  assert.equal(events.filter((event) => event.reasonCode === "SESSION_CREDENTIAL_UNSUPPORTED").length, 1);

  console.log("PASS identical sensitive-operation retries reuse one tenant-, actor- and action-scoped operation identity");
  console.log("PASS conflicting replay, ambient session credentials and oversized requests fail with bounded responses");
  console.log("PASS request deadlines abort repository work and roll back uncommitted replay receipts");
} finally {
  await timeoutApi.close();
  await api.close();
  await pool.query(
    "DELETE FROM audit.api_sensitive_operation_receipts WHERE idempotency_key_hash_sha256 = ANY($1::text[])",
    [receiptKeyHashes],
  );
  await fixture.cleanup();
  await pool.end();
}
