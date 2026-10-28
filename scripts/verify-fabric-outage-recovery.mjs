import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
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
const channelName = "tt-audit-alpha-v1";
const peerService = "peer0.alpha.audit.tenant-trust.test";
const composeArguments = ["compose", "--env-file", ".env", "-f", "infra/fabric/compose.yaml"];
const identifiers = Object.freeze({
  event: `evt_${randomUUID()}`,
  decision: `dec_${randomUUID()}`,
  request: `req_${randomUUID()}`,
  correlation: `cor_${randomUUID()}`,
});
const now = new Date();
const event = Object.freeze({
  schemaVersion: "1.0.0",
  eventId: identifiers.event,
  eventType: "access.decided.v1",
  tenantId,
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  aggregateId: identifiers.decision,
  correlationId: identifiers.correlation,
  causationId: "evt_018f1234-5678-7abc-8def-0123456789dc",
  idempotencyKey: `fabric-outage-recovery:${identifiers.decision}`,
  occurredAt: now.toISOString(),
  recordedAt: new Date(now.getTime() + 1).toISOString(),
  producer: { service: "authorization-api", instanceId: "fabric-outage-verifier" },
  payload: {
    decisionId: identifiers.decision,
    requestId: identifiers.request,
    certificateId: "crt_018f1234-5678-7abc-8def-0123456789d1",
    trustTransitionId: "trn_018f1234-5678-7abc-8def-0123456789d4",
    trustScore: 69,
    policyVersionId: "pol_018f1234-5678-7abc-8def-0123456789d5",
    operation: "profile:read",
    resourceType: "subject-profile",
    resourceIdHashSha256: "de".repeat(32),
    outcome: "ALLOW",
    reasonCodes: ["TRUST_AND_CONTEXT_SATISFIED"],
    stepUpProofIdHashSha256: null,
  },
});

function execute(command, args, label, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${label} failed:\n${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
}

function compose(args, label) {
  return execute("docker", [...composeArguments, ...args], label);
}

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function peerContainerId() {
  return compose(["ps", "-a", "-q", peerService], "Fabric peer lookup");
}

function peerHealth() {
  const containerId = peerContainerId();
  if (!containerId) return "missing";
  return execute(
    "docker",
    ["inspect", "--format", "{{if .State.Running}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}stopped{{end}}", containerId],
    "Fabric peer health check",
  );
}

function waitForHealthyPeer(timeoutMilliseconds = 60_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  let health = peerHealth();
  while (health !== "healthy" && Date.now() < deadline) {
    sleep(1_000);
    health = peerHealth();
  }
  assert.equal(health, "healthy", `tenant Alpha peer did not become healthy (last state: ${health})`);
}

const pool = new Pool({
  host: "127.0.0.1",
  port: Number(environment.POSTGRES_HOST_PORT),
  database: environment.POSTGRES_DB,
  user: environment.POSTGRES_USER,
  password: environment.POSTGRES_PASSWORD,
  max: 2,
  application_name: "fabric-outage-recovery-verifier",
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
const outbox = createPostgresAuditOutboxWorkerRepository({ query: workerQuery });
let outageGateway;
let recoveryGateway;
let peerStopped = false;
let recoveryStartedAt;
let recoveryTimeMilliseconds;

try {
  assert.equal(peerHealth(), "healthy", "the tenant Alpha peer must be healthy before the outage exercise");
  const initialStatus = await outbox.deliveryStatus();
  assert.deepEqual(initialStatus.gaps, [], "resolve existing audit-delivery gaps before the outage exercise");

  compose(["stop", peerService], "tenant Alpha peer stop");
  peerStopped = true;
  assert.equal(peerHealth(), "stopped");

  const authorization = execute(
    process.execPath,
    ["scripts/verify-adaptive-authorization-scenario.mjs"],
    "authorization scenario during the Fabric outage",
  );
  assert.match(authorization, /PASS one valid certificate receives normal profile access/u);
  assert.match(authorization, /PASS the same certificate is then quarantined/u);

  const queued = await inRole("tenant_trust_app", async (query) => {
    await query("SELECT identity.set_tenant_context($1)", [tenantId]);
    const repository = createPostgresAuditOutboxEnqueueRepository({ query });
    return createAuditCommitmentEnqueuer({ enqueue: repository.enqueue })
      .enqueueEvent({ channelName, event });
  });
  assert.equal(queued.status, "pending");

  outageGateway = await connectFabricAuditGatewayFromEnvironment({
    environment: { ...process.env, ...environment, FABRIC_GATEWAY_REQUEST_TIMEOUT_MS: "5000" },
    repositoryRoot,
  });
  const outageWorker = createAuditOutboxWorker({
    workerId: "audit-worker.verify-real-outage",
    outbox,
    gateway: outageGateway,
  });
  const failed = await outageWorker.runOnce();
  assert.equal(failed.status, "failed");
  assert.equal(failed.eventId, identifiers.event);
  assert.equal(failed.failureCode, "SUBMISSION_FAILED");

  const visibleGap = await outbox.deliveryStatus();
  assert.equal(visibleGap.gaps.length, 1);
  assert.deepEqual(
    {
      eventId: visibleGap.gaps[0].eventId,
      status: visibleGap.gaps[0].status,
      attemptCount: visibleGap.gaps[0].attemptCount,
      lastFailureCode: visibleGap.gaps[0].lastFailureCode,
    },
    {
      eventId: identifiers.event,
      status: "failed",
      attemptCount: 1,
      lastFailureCode: "SUBMISSION_FAILED",
    },
  );

  outageGateway.close();
  outageGateway = undefined;
  recoveryStartedAt = process.hrtime.bigint();
  compose(["start", peerService], "tenant Alpha peer recovery");
  peerStopped = false;
  waitForHealthyPeer();

  await pool.query(
    `UPDATE audit.fabric_commitment_outbox
     SET next_attempt_at = created_at, updated_at = GREATEST(updated_at, clock_timestamp())
     WHERE tenant_id = $1 AND event_id = $2 AND status = 'failed'`,
    [tenantId, identifiers.event],
  );
  recoveryGateway = await connectFabricAuditGatewayFromEnvironment({
    environment: { ...process.env, ...environment },
    repositoryRoot,
  });
  const recoveryWorker = createAuditOutboxWorker({
    workerId: "audit-worker.verify-recovered-peer",
    outbox,
    gateway: recoveryGateway,
  });
  const delivered = await recoveryWorker.runOnce();
  assert.equal(delivered.status, "committed");
  assert.equal(delivered.eventId, identifiers.event);
  recoveryTimeMilliseconds = Number(process.hrtime.bigint() - recoveryStartedAt) / 1_000_000;

  const stored = await pool.query(
    `SELECT status, attempt_count, validation_code, block_number::text, confirmation_source,
            last_failure_code, ledger_value
     FROM audit.fabric_commitment_outbox
     WHERE tenant_id = $1 AND event_id = $2`,
    [tenantId, identifiers.event],
  );
  assert.equal(stored.rows.length, 1);
  assert.deepEqual(
    {
      status: stored.rows[0].status,
      attemptCount: stored.rows[0].attempt_count,
      validationCode: stored.rows[0].validation_code,
      blockNumber: stored.rows[0].block_number,
      confirmationSource: stored.rows[0].confirmation_source,
      lastFailureCode: stored.rows[0].last_failure_code,
    },
    {
      status: "committed",
      attemptCount: 2,
      validationCode: 0,
      blockNumber: delivered.blockNumber,
      confirmationSource: delivered.confirmationSource,
      lastFailureCode: null,
    },
  );
  assert.deepEqual(
    await recoveryGateway.readCommitment({
      tenantId,
      recordType: "access-decision",
      eventKeyHashSha256: queued.ledgerKey.slice(queued.ledgerKey.lastIndexOf("~") + 1),
    }),
    stored.rows[0].ledger_value,
  );
  assert.deepEqual((await outbox.deliveryStatus()).gaps, []);

  console.log("PASS authorization completed while the tenant Alpha Fabric peer was stopped");
  console.log("PASS the access-decision commitment stayed durable and visible as a failed outbox delivery");
  console.log("PASS peer recovery committed the same event and the ledger value matches PostgreSQL");
  console.log("PASS the delivery verifier reports no remaining audit gaps");
  console.log(`MEASURE fabric-outage-recovery-time-ms ${recoveryTimeMilliseconds.toFixed(3)}`);
} finally {
  outageGateway?.close();
  recoveryGateway?.close();
  if (peerStopped) {
    compose(["start", peerService], "tenant Alpha peer restoration");
    waitForHealthyPeer();
  }
  await pool.query(
    "DELETE FROM audit.fabric_commitment_outbox WHERE tenant_id = $1 AND event_id = $2",
    [tenantId, identifiers.event],
  ).catch(() => {});
  await pool.end();
}
