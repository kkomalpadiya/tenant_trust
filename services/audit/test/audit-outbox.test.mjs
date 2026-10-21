import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import {
  AuditOutboxError,
  createAuditCommitmentEnqueuer,
  createAuditOutboxWorker,
  createPostgresAuditOutboxEnqueueRepository,
  createPostgresAuditOutboxWorkerRepository,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789ab",
  event: "evt_018f1234-5678-7abc-8def-0123456789ab",
  causation: "evt_018f1234-5678-7abc-8def-0123456789ac",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
  claim: "clm_018f1234-5678-7abc-8def-0123456789ab",
});

function trustEvent(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    eventId: ids.event,
    eventType: "trust.updated.v1",
    tenantId: ids.tenant,
    subjectId: ids.subject,
    aggregateId: ids.transition,
    correlationId: ids.correlation,
    causationId: ids.causation,
    idempotencyKey: "trust:transition:audit-outbox-1",
    occurredAt: "2026-10-21T08:00:00.000Z",
    recordedAt: "2026-10-21T08:00:00.100Z",
    producer: { service: "trust-engine", instanceId: "trust-1" },
    payload: {
      transitionId: ids.transition,
      previousScore: 86,
      newScore: 62,
      previousBand: "trusted",
      newBand: "restricted",
      modelVersion: "1.0.0",
      configurationVersion: 3,
      evidenceIds: [ids.evidence],
      explanationHashSha256: "ab".repeat(32),
    },
    ...overrides,
  };
}

function claim(overrides = {}) {
  const event = trustEvent();
  const commitment = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event });
  return {
    tenantId: ids.tenant,
    eventId: ids.event,
    channelName: "tt-audit-alpha-v1",
    event,
    canonicalPreimageJson: commitment.canonicalPreimageJson,
    ledgerKey: commitment.ledgerKey,
    ledgerValue: commitment.ledgerValue,
    claimToken: ids.claim,
    attemptCount: 1,
    ...overrides,
  };
}

test("enqueue builds and durably stores a commitment without contacting Fabric", async () => {
  const calls = [];
  const enqueuer = createAuditCommitmentEnqueuer({
    async enqueue(request) {
      calls.push(request);
      return { eventId: request.event.eventId, status: "pending" };
    },
  });

  const result = await enqueuer.enqueueEvent({ channelName: "tt-audit-alpha-v1", event: trustEvent() });
  assert.equal(result.status, "pending");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].commitment.ledgerValue.recordType, "trust-transition");
  assert.equal(JSON.stringify(calls[0].commitment.ledgerValue).includes(ids.tenant), false);
});

test("worker submits one claim and persists the exact idempotent response", async () => {
  const calls = [];
  const current = claim();
  const worker = createAuditOutboxWorker({
    workerId: "audit-worker.local-1",
    outbox: {
      async claimNext(request) {
        calls.push(["claim", request]);
        return current;
      },
      async markSubmitted(request) {
        calls.push(["submitted", request]);
        return { eventId: request.eventId, status: "submitted", submissionStatus: request.submissionStatus };
      },
      async markFailed() {
        assert.fail("successful submission must not schedule a retry");
      },
    },
    gateway: {
      async submitCommitment(request) {
        calls.push(["gateway", request]);
        return { ledgerKey: current.ledgerKey, status: "created" };
      },
    },
  });

  const result = await worker.runOnce();
  assert.equal(result.status, "submitted");
  assert.equal(result.submissionStatus, "created");
  assert.deepEqual(calls.map(([name]) => name), ["claim", "gateway", "submitted"]);
  assert.deepEqual(calls[1][1], { tenantId: ids.tenant, ledgerValue: current.ledgerValue });
});

test("a duplicate chaincode response completes a crash-recovered delivery", async () => {
  const current = claim({ attemptCount: 2 });
  const worker = createAuditOutboxWorker({
    workerId: "audit-worker.local-1",
    outbox: {
      claimNext: async () => current,
      markSubmitted: async (request) => ({
        eventId: request.eventId,
        status: "submitted",
        submissionStatus: request.submissionStatus,
      }),
      markFailed: async () => assert.fail("duplicate is a successful idempotent delivery"),
    },
    gateway: { submitCommitment: async () => ({ ledgerKey: current.ledgerKey, status: "duplicate" }) },
  });
  const result = await worker.runOnce();
  assert.equal(result.status, "submitted");
  assert.equal(result.submissionStatus, "duplicate");
  assert.equal(result.attemptCount, 2);
});

test("Fabric outage is isolated and schedules bounded exponential retry", async () => {
  const failures = [];
  const current = claim({ attemptCount: 4 });
  const worker = createAuditOutboxWorker({
    workerId: "audit-worker.local-1",
    outbox: {
      claimNext: async () => current,
      markSubmitted: async () => assert.fail("outage cannot mark submitted"),
      async markFailed(request) {
        failures.push(request);
        return { eventId: request.eventId, status: "pending", nextAttemptAt: "2026-10-21T08:00:40.000Z" };
      },
    },
    gateway: {
      async submitCommitment() {
        throw Object.assign(new Error("private network detail"), { reasonCode: "SUBMISSION_FAILED" });
      },
    },
  });
  const result = await worker.runOnce();
  assert.equal(result.status, "retry-scheduled");
  assert.equal(result.failureCode, "SUBMISSION_FAILED");
  assert.equal(failures[0].retryDelaySeconds, 40);
  assert.equal(JSON.stringify(result).includes("private network detail"), false);
});

test("untrusted errors are reduced to a safe failure code and retry caps at ten minutes", async () => {
  const current = claim({ attemptCount: 40 });
  let failure;
  const worker = createAuditOutboxWorker({
    workerId: "audit-worker.local-1",
    outbox: {
      claimNext: async () => current,
      markSubmitted: async () => assert.fail("invalid response cannot be submitted"),
      async markFailed(request) {
        failure = request;
        return { eventId: request.eventId, status: "pending", nextAttemptAt: "2026-10-21T08:10:00.000Z" };
      },
    },
    gateway: { submitCommitment: async () => ({ ledgerKey: "wrong", status: "created" }) },
  });
  const result = await worker.runOnce();
  assert.equal(failure.failureCode, "FABRIC_RESPONSE_INVALID");
  assert.equal(failure.retryDelaySeconds, 600);
  assert.equal(result.status, "retry-scheduled");
});

test("idle poll performs no Fabric or status operation", async () => {
  const worker = createAuditOutboxWorker({
    workerId: "audit-worker.local-1",
    outbox: {
      claimNext: async () => null,
      markSubmitted: async () => assert.fail("idle worker cannot submit"),
      markFailed: async () => assert.fail("idle worker cannot fail"),
    },
    gateway: { submitCommitment: async () => assert.fail("idle worker cannot contact Fabric") },
  });
  assert.deepEqual(await worker.runOnce(), { status: "idle" });
});

test("PostgreSQL enqueue adapter sends only parameters and accepts idempotent state", async () => {
  const event = trustEvent();
  const commitment = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event });
  const calls = [];
  const repository = createPostgresAuditOutboxEnqueueRepository({
    clock: () => new Date("2026-10-21T08:00:00.200Z"),
    async query(sql, params) {
      calls.push({ sql, params });
      return { rows: [{
        event_id: ids.event,
        status: "pending",
        event_key_hash_sha256: commitment.ledgerValue.eventKeyHashSha256,
        commitment_hash_sha256: commitment.ledgerValue.commitmentHashSha256,
      }] };
    },
  });
  const result = await repository.enqueue({ channelName: "tt-audit-alpha-v1", event, commitment });
  assert.equal(result.status, "pending");
  assert.equal(calls[0].sql.includes(ids.tenant), false);
  assert.equal(calls[0].sql.includes("$1"), true);
  assert.equal(calls[0].params[0], ids.tenant);
  assert.equal(calls[0].params[11], "2026-10-21T08:00:00.200Z");
});

test("PostgreSQL worker adapter uses restricted claim, success and failure functions", async () => {
  const current = claim();
  const calls = [];
  const repository = createPostgresAuditOutboxWorkerRepository({
    idFactory: () => "018f1234-5678-7abc-8def-0123456789ab",
    clock: () => new Date("2026-10-21T08:00:01.000Z"),
    async query(sql, params) {
      calls.push({ sql, params });
      if (sql.includes("claim_fabric_commitment")) return { rows: [{
        tenant_id: current.tenantId,
        event_id: current.eventId,
        channel_name: current.channelName,
        event_document: current.event,
        canonical_preimage_json: current.canonicalPreimageJson,
        ledger_key: current.ledgerKey,
        ledger_value: current.ledgerValue,
        claim_token: current.claimToken,
        attempt_count: "1",
      }] };
      if (sql.includes("submitted")) return { rows: [{
        event_id: ids.event, status: "submitted", submission_status: "created",
      }] };
      return { rows: [{
        event_id: ids.event, status: "pending", next_attempt_at: "2026-10-21T08:00:06.000Z",
      }] };
    },
  });
  const claimed = await repository.claimNext({ workerId: "audit-worker.local-1" });
  assert.equal(claimed.claimToken, ids.claim);
  await repository.markSubmitted({
    tenantId: ids.tenant,
    eventId: ids.event,
    claimToken: ids.claim,
    ledgerKey: current.ledgerKey,
    submissionStatus: "created",
  });
  await repository.markFailed({
    tenantId: ids.tenant,
    eventId: ids.event,
    claimToken: ids.claim,
    failureCode: "SUBMISSION_FAILED",
    retryDelaySeconds: 5,
  });
  assert.equal(calls.length, 3);
  assert.equal(calls.every(({ sql }) => sql.includes("$1") && !sql.includes(ids.tenant)), true);
});

test("invalid claims and enqueuer acknowledgements fail closed", async () => {
  const event = trustEvent();
  const enqueuer = createAuditCommitmentEnqueuer({
    enqueue: async () => ({ eventId: "evt_018f1234-5678-7abc-8def-0123456789ff", status: "pending" }),
  });
  await assert.rejects(
    enqueuer.enqueueEvent({ channelName: "tt-audit-alpha-v1", event }),
    (error) => error instanceof AuditOutboxError && error.reasonCode === "OUTBOX_ENQUEUE_INVALID",
  );
  const repository = createPostgresAuditOutboxWorkerRepository({
    query: async () => ({ rows: [{ ...claim(), tenant_id: "wrong" }] }),
  });
  await assert.rejects(
    repository.claimNext({ workerId: "audit-worker.local-1" }),
    (error) => error instanceof AuditOutboxError && error.reasonCode === "OUTBOX_SOURCE_INVALID",
  );
});
