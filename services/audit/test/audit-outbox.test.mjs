import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import { createAuditCommitmentEnqueuer, createAuditOutboxWorker,
  createPostgresAuditOutboxWorkerRepository } from "../src/index.mjs";

const ids = Object.freeze({ tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  event: "evt_018f1234-5678-7abc-8def-0123456789ab", claim: "clm_018f1234-5678-7abc-8def-0123456789ab",
  transaction: "c".repeat(64) });
const event = Object.freeze({ schemaVersion: "1.0.0",eventId: ids.event,eventType: "trust.updated.v1",tenantId: ids.tenant,
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",aggregateId: "trn_018f1234-5678-7abc-8def-0123456789ab",
  correlationId: "cor_018f1234-5678-7abc-8def-0123456789ab",causationId: "evt_018f1234-5678-7abc-8def-0123456789ac",
  idempotencyKey: "trust:transition:audit-outbox-1",occurredAt: "2026-10-21T08:00:00.000Z",recordedAt: "2026-10-21T08:00:00.100Z",
  producer: { service: "trust-engine",instanceId: "trust-1" },payload: { transitionId: "trn_018f1234-5678-7abc-8def-0123456789ab",
    previousScore: 86,newScore: 62,previousBand: "trusted",newBand: "restricted",modelVersion: "1.0.0",configurationVersion: 3,
    evidenceIds: ["evd_018f1234-5678-7abc-8def-0123456789ab"],explanationHashSha256: "ab".repeat(32) } });
const commitment = buildAuditCommitment({ channelName: "tt-audit-alpha-v1",event });
function claim(overrides = {}) { return { tenantId: ids.tenant,eventId: ids.event,channelName: "tt-audit-alpha-v1",event,
  canonicalPreimageJson: commitment.canonicalPreimageJson,ledgerKey: commitment.ledgerKey,ledgerValue: commitment.ledgerValue,
  claimToken: ids.claim,attemptCount: 1,...overrides }; }
function outbox(overrides = {}) { return { claimConfirmation: async () => null,claimNext: async () => claim(),
  recordSubmission: async () => ({ status: "confirming" }),markCommitted: async () => ({ status: "committed" }),
  markCommitFailed: async () => ({ status: "failed",nextAttemptAt: "2026-10-21T08:00:05.000Z" }),
  markConfirmationPending: async () => ({ status: "submitted",nextConfirmationAt: "2026-10-21T08:00:05.000Z" }),
  markFailed: async () => ({ status: "failed",nextAttemptAt: "2026-10-21T08:00:05.000Z" }),...overrides }; }
function gateway(overrides = {}) { return { queryTransactionStatus: async () => assert.fail("no gap expected"),
  submitCommitment: async () => ({ ledgerKey: commitment.ledgerKey,status: "created",transactionId: ids.transaction,
    waitForCommit: async () => ({ transactionId: ids.transaction,validationCode: 0,successful: true,blockNumber: "42",source: "gateway-status" }) }),
  ...overrides }; }

test("enqueue stores a commitment without contacting Fabric", async () => {
  let stored;
  const result = await createAuditCommitmentEnqueuer({ enqueue: async (value) => { stored = value; return { eventId: ids.event,status: "pending" }; } })
    .enqueueEvent({ channelName: "tt-audit-alpha-v1",event });
  assert.equal(result.status, "pending");
  assert.equal(stored.commitment.ledgerValue.recordType, "trust-transition");
});

test("worker marks committed only after the Gateway commit status succeeds", async () => {
  const calls = [];
  const worker = createAuditOutboxWorker({ workerId: "audit-worker.local-1",outbox: outbox({
    recordSubmission: async () => { calls.push("submitted"); return { status: "confirming" }; },
    markCommitted: async () => { calls.push("committed"); return { status: "committed" }; },
  }),gateway: gateway({ submitCommitment: async () => ({ ledgerKey: commitment.ledgerKey,status: "created",transactionId: ids.transaction,
    waitForCommit: async () => { calls.push("commit-status"); return { transactionId: ids.transaction,validationCode: 0,
      blockNumber: "42",source: "gateway-status" }; } }) }) });
  const result = await worker.runOnce();
  assert.equal(result.status, "committed");
  assert.deepEqual(calls, ["submitted","commit-status","committed"]);
});

test("commit status outage leaves a durable transaction gap for restart", async () => {
  let pending;
  const worker = createAuditOutboxWorker({ workerId: "audit-worker.local-1",outbox: outbox({
    markConfirmationPending: async (value) => { pending = value; return { status: "submitted",nextConfirmationAt: "2026-10-21T08:00:05.000Z" }; },
  }),gateway: gateway({ submitCommitment: async () => ({ ledgerKey: commitment.ledgerKey,status: "created",transactionId: ids.transaction,
    waitForCommit: async () => { throw Object.assign(new Error("offline"), { reasonCode: "COMMIT_STATUS_UNAVAILABLE" }); } }) }) });
  const result = await worker.runOnce();
  assert.equal(result.status, "confirmation-pending");
  assert.equal(pending.transactionId, ids.transaction);
});

test("restarted worker reconciles the stored transaction through QSCC", async () => {
  const calls = [];
  const gap = { tenantId: ids.tenant,eventId: ids.event,transactionId: ids.transaction,claimToken: ids.claim,attemptCount: 1 };
  const worker = createAuditOutboxWorker({ workerId: "audit-worker.local-1",outbox: outbox({ claimConfirmation: async () => gap,
    claimNext: async () => assert.fail("reconciliation has priority"),markCommitted: async (value) => { calls.push(value); return { status: "committed" }; } }),
  gateway: gateway({ queryTransactionStatus: async () => ({ transactionId: ids.transaction,validationCode: 0,
    blockNumber: "43",source: "qscc" }),submitCommitment: async () => assert.fail("must not resubmit a known transaction") }) });
  const result = await worker.runOnce();
  assert.equal(result.status, "committed");
  assert.equal(result.confirmationSource, "qscc");
  assert.equal(calls[0].transactionId, ids.transaction);
});

test("invalid Fabric validation is visible as failed and scheduled for retry", async () => {
  let failure;
  const worker = createAuditOutboxWorker({ workerId: "audit-worker.local-1",outbox: outbox({ markCommitFailed: async (value) => {
    failure = value; return { status: "failed",nextAttemptAt: "2026-10-21T08:00:05.000Z" }; } }),gateway: gateway({
    submitCommitment: async () => ({ ledgerKey: commitment.ledgerKey,status: "created",transactionId: ids.transaction,
      waitForCommit: async () => ({ transactionId: ids.transaction,validationCode: 11,blockNumber: "44",source: "gateway-status" }) }) }) });
  const result = await worker.runOnce();
  assert.equal(result.status, "failed");
  assert.equal(failure.validationCode, 11);
});

test("PostgreSQL adapter exposes constrained status functions", async () => {
  const sql = [];
  const repository = createPostgresAuditOutboxWorkerRepository({ query: async (text) => { sql.push(text);
    if (text.includes("delivery_summary")) return { rows: [{ status: "failed",event_count: "1",oldest_event_at: "2026-10-21T08:00:00Z" }] };
    return { rows: [{ tenant_id: ids.tenant,event_id: ids.event,status: "failed",attempt_count: "1",transaction_id: null,
      last_failure_code: "SUBMISSION_FAILED",updated_at: "2026-10-21T08:00:01Z" }] }; } });
  const status = await repository.deliveryStatus();
  assert.equal(status.summary[0].eventCount, 1);
  assert.equal(status.gaps[0].lastFailureCode, "SUBMISSION_FAILED");
  assert.equal(sql.every((text) => text.startsWith("SELECT * FROM audit.")), true);
});
