import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import { connectFabricAuditGatewayFromEnvironment } from "../apps/api/src/fabric-audit-gateway.mjs";
import {
  createAuditCommitmentEnqueuer,
  createAuditOutboxWorker,
  createPostgresAuditOutboxEnqueueRepository,
  createPostgresAuditOutboxWorkerRepository,
} from "../services/audit/src/index.mjs";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const tenantId = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const subjectId = "sub_018f1234-5678-7abc-8def-0123456789ab";
const channelName = "tt-audit-alpha-v1";

function scoreArgument(name, fallback) {
  const position = process.argv.indexOf(name);
  if (position === -1) return fallback;
  const value = Number(process.argv[position + 1]);
  if (!Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error(`${name} must be a number from 0 to 100.`);
  }
  return value;
}

function trustBand(score) {
  if (score >= 80) return "trusted";
  if (score >= 65) return "conditional";
  if (score >= 50) return "restricted";
  return "quarantine";
}

function printField(label, value) {
  console.log(`${label.padEnd(22)} ${value}`);
}

const previousScore = scoreArgument("--previous-score", 86);
const newScore = scoreArgument("--new-score", 62);
const eventUuid = randomUUID();
const transitionUuid = randomUUID();
const evidenceUuid = randomUUID();
const eventId = `evt_${eventUuid}`;
const transitionId = `trn_${transitionUuid}`;
const evidenceId = `evd_${evidenceUuid}`;
const occurredAt = new Date();
const recordedAt = new Date(occurredAt.getTime() + 1);
const explanationHashSha256 = createHash("sha256")
  .update(JSON.stringify({ evidenceId, previousScore, newScore }))
  .digest("hex");

const event = Object.freeze({
  schemaVersion: "1.0.0",
  eventId,
  eventType: "trust.updated.v1",
  tenantId,
  subjectId,
  aggregateId: transitionId,
  correlationId: `cor_${randomUUID()}`,
  causationId: `evt_${randomUUID()}`,
  idempotencyKey: `fabric-audit-demo:${eventId}:v1`,
  occurredAt: occurredAt.toISOString(),
  recordedAt: recordedAt.toISOString(),
  producer: { service: "fabric-audit-demo", instanceId: "presenter-1" },
  payload: {
    transitionId,
    previousScore,
    newScore,
    previousBand: trustBand(previousScore),
    newBand: trustBand(newScore),
    modelVersion: "1.0.0",
    configurationVersion: 1,
    evidenceIds: [evidenceId],
    explanationHashSha256,
  },
});

const expectedCommitment = buildAuditCommitment({ channelName, event });
const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  application_name: "fabric-audit-demo",
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
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

const workerQuery = (text, values) => inRole(
  "tenant_trust_audit_outbox_worker",
  (query) => query(text, values),
);

let gateway;
try {
  const queued = await inRole("tenant_trust_app", async (query) => {
    await query("SELECT identity.set_tenant_context($1)", [tenantId]);
    const repository = createPostgresAuditOutboxEnqueueRepository({ query });
    return createAuditCommitmentEnqueuer({ enqueue: repository.enqueue })
      .enqueueEvent({ channelName, event });
  });
  assert.equal(queued.status, "pending");

  gateway = await connectFabricAuditGatewayFromEnvironment({
    environment: { ...process.env, ...environment },
    repositoryRoot,
  });
  const repository = createPostgresAuditOutboxWorkerRepository({ query: workerQuery });
  const worker = createAuditOutboxWorker({
    workerId: `audit-worker.demo-${eventUuid.slice(0, 8)}`,
    outbox: repository,
    gateway,
  });

  let stored;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    await worker.runOnce();
    const result = await pool.query(
      `SELECT status, attempt_count, submission_status, transaction_id, validation_code,
         block_number::text, confirmation_source, last_failure_code,
         commitment_hash_sha256, event_key_hash_sha256, ledger_value
       FROM audit.fabric_commitment_outbox
       WHERE tenant_id = $1 AND event_id = $2`,
      [tenantId, eventId],
    );
    stored = result.rows[0];
    if (stored?.status === "committed") break;
    if (stored?.status === "failed") {
      throw new Error(`Fabric delivery failed: ${stored.last_failure_code ?? "UNKNOWN_FAILURE"}`);
    }
  }

  assert(stored, "The audit outbox row was not found.");
  assert.equal(stored.status, "committed", "The event was not committed after 100 worker cycles.");
  assert.equal(stored.validation_code, 0);
  assert.equal(stored.commitment_hash_sha256, expectedCommitment.ledgerValue.commitmentHashSha256);
  assert.equal(stored.event_key_hash_sha256, expectedCommitment.ledgerValue.eventKeyHashSha256);

  const ledgerValue = await gateway.readCommitment({
    tenantId,
    recordType: expectedCommitment.ledgerValue.recordType,
    eventKeyHashSha256: expectedCommitment.ledgerValue.eventKeyHashSha256,
  });
  assert.deepEqual(ledgerValue, expectedCommitment.ledgerValue);
  assert.deepEqual(stored.ledger_value, expectedCommitment.ledgerValue);

  console.log("\nFABRIC AUDIT PROOF - VERIFIED\n");
  printField("Action", "Trust score updated");
  printField("Trust transition", `${previousScore} (${trustBand(previousScore)}) -> ${newScore} (${trustBand(newScore)})`);
  printField("Event ID", eventId);
  printField("Channel", channelName);
  printField("Outbox status", stored.status);
  printField("Transaction ID", stored.transaction_id);
  printField("Block number", stored.block_number);
  printField("Validation code", `${stored.validation_code} (valid)`);
  printField("Confirmation source", stored.confirmation_source);
  printField("Commitment SHA-256", stored.commitment_hash_sha256);
  printField("Ledger read-back", "MATCHED - Fabric stored the same commitment");
  console.log("\nThe committed outbox row was retained for your demonstration.");
} finally {
  gateway?.close();
  await pool.end();
}
