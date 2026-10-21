import assert from "node:assert/strict";
import { Pool } from "pg";
import { connectFabricAuditGatewayFromEnvironment } from "../apps/api/src/fabric-audit-gateway.mjs";
import {
  createAuditCommitmentEnqueuer,
  createAuditOutboxWorker,
  createPostgresAuditOutboxEnqueueRepository,
  createPostgresAuditOutboxWorkerRepository,
} from "../services/audit/src/index.mjs";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const tenantId = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const eventId = "evt_018f1234-5678-7abc-8def-0123456789f6";
const event = Object.freeze({
  schemaVersion: "1.0.0",
  eventId,
  eventType: "trust.updated.v1",
  tenantId,
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  aggregateId: "trn_018f1234-5678-7abc-8def-0123456789f6",
  correlationId: "cor_018f1234-5678-7abc-8def-0123456789f6",
  causationId: "evt_018f1234-5678-7abc-8def-0123456789f7",
  idempotencyKey: "trust:transition:audit-worker-verification-v1",
  occurredAt: "2026-10-21T08:00:00.000Z",
  recordedAt: "2026-10-21T08:00:00.100Z",
  producer: { service: "trust-engine", instanceId: "audit-worker-verifier" },
  payload: {
    transitionId: "trn_018f1234-5678-7abc-8def-0123456789f6",
    previousScore: 81,
    newScore: 58,
    previousBand: "trusted",
    newBand: "restricted",
    modelVersion: "1.0.0",
    configurationVersion: 1,
    evidenceIds: ["evd_018f1234-5678-7abc-8def-0123456789f6"],
    explanationHashSha256: "c6".repeat(32),
  },
});

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  application_name: "audit-outbox-verifier",
});

async function inRole(role, work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SET LOCAL ROLE ${role}`);
    const result = await work((text, values) => client.query(text, values));
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Keep the original verification failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

const workerQuery = (text, values) => inRole(
  "tenant_trust_audit_outbox_worker",
  (query) => query(text, values),
);
const gateway = await connectFabricAuditGatewayFromEnvironment({
  environment: { ...process.env, ...environment },
  repositoryRoot,
});

try {
  await pool.query(
    "DELETE FROM audit.fabric_commitment_outbox WHERE tenant_id = $1 AND event_id = $2",
    [tenantId, eventId],
  );

  const queued = await inRole("tenant_trust_app", async (query) => {
    await query("SELECT identity.set_tenant_context($1)", [tenantId]);
    const repository = createPostgresAuditOutboxEnqueueRepository({ query });
    return createAuditCommitmentEnqueuer({ enqueue: repository.enqueue })
      .enqueueEvent({ channelName: "tt-audit-alpha-v1", event });
  });
  assert.equal(queued.status, "pending");

  const repository = createPostgresAuditOutboxWorkerRepository({ query: workerQuery });
  const unavailableWorker = createAuditOutboxWorker({
    workerId: "audit-worker.verify-live",
    outbox: repository,
    gateway: {
      async queryTransactionStatus() {
        throw Object.assign(new Error("simulated Fabric outage"), { reasonCode: "TRANSACTION_STATUS_QUERY_FAILED" });
      },
      async submitCommitment() {
        throw Object.assign(new Error("simulated Fabric outage"), { reasonCode: "SUBMISSION_FAILED" });
      },
    },
  });
  const failed = await unavailableWorker.runOnce();
  assert.equal(failed.status, "failed");
  const persistedFailure = await pool.query(
    `SELECT status, attempt_count, last_failure_code
     FROM audit.fabric_commitment_outbox
     WHERE tenant_id = $1 AND event_id = $2`,
    [tenantId, eventId],
  );
  assert.deepEqual(persistedFailure.rows[0], {
    status: "failed",
    attempt_count: 1,
    last_failure_code: "SUBMISSION_FAILED",
  });

  await pool.query(
    `UPDATE audit.fabric_commitment_outbox
     SET next_attempt_at = created_at,
         updated_at = GREATEST(updated_at, clock_timestamp())
     WHERE tenant_id = $1 AND event_id = $2 AND status = 'failed'`,
    [tenantId, eventId],
  );
  const gapWorker = createAuditOutboxWorker({
    workerId: "audit-worker.verify-live",
    outbox: repository,
    gateway: {
      queryTransactionStatus: gateway.queryTransactionStatus,
      async submitCommitment(request) {
        const submitted = await gateway.submitCommitment(request);
        return {
          ...submitted,
          async waitForCommit() {
            await submitted.waitForCommit();
            throw Object.assign(new Error("simulated status response loss"), { reasonCode: "COMMIT_STATUS_UNAVAILABLE" });
          },
        };
      },
    },
  });
  const gap = await gapWorker.runOnce();
  assert.equal(gap.status, "confirmation-pending");
  assert.equal(typeof gap.transactionId, "string");

  const persistedGap = await pool.query(
    `SELECT status, attempt_count, transaction_id, last_failure_code
     FROM audit.fabric_commitment_outbox WHERE tenant_id = $1 AND event_id = $2`,
    [tenantId, eventId],
  );
  assert.deepEqual(persistedGap.rows[0], {
    status: "submitted",
    attempt_count: 2,
    transaction_id: gap.transactionId,
    last_failure_code: "COMMIT_STATUS_UNAVAILABLE",
  });

  await pool.query(
    `UPDATE audit.fabric_commitment_outbox SET next_confirmation_at = submitted_at,
       updated_at = GREATEST(updated_at, clock_timestamp())
     WHERE tenant_id = $1 AND event_id = $2 AND status = 'submitted'`,
    [tenantId, eventId],
  );
  const restartedWorker = createAuditOutboxWorker({ workerId: "audit-worker.verify-restarted", outbox: repository, gateway });
  const delivered = await restartedWorker.runOnce();
  assert.equal(delivered.status, "committed");
  assert.equal(delivered.transactionId, gap.transactionId);
  assert.equal(delivered.confirmationSource, "qscc");

  const stored = await pool.query(
    `SELECT status, attempt_count, submission_status, transaction_id, validation_code,
       block_number::text, confirmation_source, last_failure_code
     FROM audit.fabric_commitment_outbox
     WHERE tenant_id = $1 AND event_id = $2`,
    [tenantId, eventId],
  );
  assert.equal(stored.rows[0].status, "committed");
  assert.equal(stored.rows[0].attempt_count, 2);
  assert(new Set(["created", "duplicate"]).has(stored.rows[0].submission_status));
  assert.equal(stored.rows[0].transaction_id, gap.transactionId);
  assert.equal(stored.rows[0].validation_code, 0);
  assert.equal(stored.rows[0].block_number, delivered.blockNumber);
  assert.equal(stored.rows[0].confirmation_source, "qscc");
  assert.equal(stored.rows[0].last_failure_code, null);
  assert.deepEqual(
    await gateway.readCommitment({
      tenantId,
      recordType: "trust-transition",
      eventKeyHashSha256: queued.ledgerKey.slice(queued.ledgerKey.lastIndexOf("~") + 1),
    }),
    (await pool.query(
      "SELECT ledger_value FROM audit.fabric_commitment_outbox WHERE tenant_id = $1 AND event_id = $2",
      [tenantId, eventId],
    )).rows[0].ledger_value,
  );

  console.log("Audit outbox reconciliation verified: a failed submission stayed visible, a lost commit response persisted its transaction ID, and a restarted worker reconciled it through QSCC before marking committed.");
} finally {
  await pool.query(
    "DELETE FROM audit.fabric_commitment_outbox WHERE tenant_id = $1 AND event_id = $2",
    [tenantId, eventId],
  ).catch(() => {});
  gateway.close();
  await pool.end();
}
