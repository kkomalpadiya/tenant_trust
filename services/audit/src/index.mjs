import { randomUUID } from "node:crypto";
import {
  assertAuditLedgerValue,
  buildAuditCommitment,
} from "@tenant-trust/contracts/audit-commitments";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CLAIM_TOKEN = /^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const FAILURE_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const LEDGER_KEY = /^audit~[a-z]+(?:-[a-z]+)*~[0-9a-f]{64}$/u;
const SUBMISSION_STATUS = new Set(["created", "duplicate"]);

const ENQUEUE_SQL = `SELECT * FROM audit.enqueue_fabric_commitment(
  $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11::jsonb, $12
)`;
const CLAIM_SQL = "SELECT * FROM audit.claim_fabric_commitment($1, $2, $3)";
const MARK_SUBMITTED_SQL = "SELECT * FROM audit.mark_fabric_commitment_submitted($1, $2, $3, $4, $5, $6)";
const MARK_FAILED_SQL = "SELECT * FROM audit.mark_fabric_commitment_failed($1, $2, $3, $4, $5, $6)";

export const AUDIT_OUTBOX_POLICY = Object.freeze({
  claimLeaseSeconds: 300,
  initialRetryDelaySeconds: 5,
  maximumRetryDelaySeconds: 600,
  delivery: "at-least-once",
});

export class AuditOutboxError extends Error {
  constructor(reasonCode, options) {
    super("The asynchronous audit operation failed.", options);
    this.name = "AuditOutboxError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new AuditOutboxError(reasonCode, cause === undefined ? undefined : { cause });
}

function requireQueryResult(result, reasonCode, expectedRows = 1) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== expectedRows) fail(reasonCode);
  return result.rows[0];
}

function asIsoTimestamp(value) {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) fail("OUTBOX_SOURCE_INVALID");
  return timestamp.toISOString();
}

function retryDelaySeconds(attemptCount) {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) fail("OUTBOX_SOURCE_INVALID");
  return Math.min(
    AUDIT_OUTBOX_POLICY.maximumRetryDelaySeconds,
    AUDIT_OUTBOX_POLICY.initialRetryDelaySeconds * (2 ** Math.min(attemptCount - 1, 30)),
  );
}

function failureCodeFor(error) {
  const reasonCode = error && typeof error === "object" ? error.reasonCode : undefined;
  return FAILURE_CODE.test(reasonCode ?? "") ? reasonCode : "FABRIC_SUBMISSION_FAILED";
}

function rowToClaim(row) {
  if (!row) return null;
  const attemptCount = Number(row.attempt_count);
  if (!TENANT_ID.test(row.tenant_id ?? "")
      || !EVENT_ID.test(row.event_id ?? "")
      || !CLAIM_TOKEN.test(row.claim_token ?? "")
      || !LEDGER_KEY.test(row.ledger_key ?? "")
      || !Number.isSafeInteger(attemptCount)
      || attemptCount < 1
      || !row.event_document
      || !row.ledger_value) {
    fail("OUTBOX_SOURCE_INVALID");
  }
  assertAuditLedgerValue(row.ledger_value);
  if (row.ledger_key !== `audit~${row.ledger_value.recordType}~${row.ledger_value.eventKeyHashSha256}`) {
    fail("OUTBOX_SOURCE_INVALID");
  }
  return Object.freeze({
    tenantId: row.tenant_id,
    eventId: row.event_id,
    channelName: row.channel_name,
    event: Object.freeze(structuredClone(row.event_document)),
    canonicalPreimageJson: row.canonical_preimage_json,
    ledgerKey: row.ledger_key,
    ledgerValue: Object.freeze(structuredClone(row.ledger_value)),
    claimToken: row.claim_token,
    attemptCount,
  });
}

export function createPostgresAuditOutboxEnqueueRepository({ query, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof clock !== "function") {
    throw new TypeError("A transaction-bound PostgreSQL query function and clock are required.");
  }
  return Object.freeze({
    async enqueue({ channelName, event, commitment }, { signal } = {}) {
      const queuedAt = clock().toISOString();
      const result = await query(ENQUEUE_SQL, [
        event.tenantId,
        event.eventId,
        channelName,
        event.eventType,
        commitment.ledgerValue.recordType,
        JSON.stringify(event),
        commitment.canonicalPreimageJson,
        commitment.ledgerKey,
        commitment.ledgerValue.eventKeyHashSha256,
        commitment.ledgerValue.commitmentHashSha256,
        JSON.stringify(commitment.ledgerValue),
        queuedAt,
      ], { signal });
      const row = requireQueryResult(result, "OUTBOX_ENQUEUE_INVALID");
      if (row.event_id !== event.eventId
          || !new Set(["pending", "submitting", "submitted"]).has(row.status)
          || row.event_key_hash_sha256 !== commitment.ledgerValue.eventKeyHashSha256
          || row.commitment_hash_sha256 !== commitment.ledgerValue.commitmentHashSha256) {
        fail("OUTBOX_ENQUEUE_INVALID");
      }
      return Object.freeze({ eventId: row.event_id, status: row.status });
    },
  });
}

export function createPostgresAuditOutboxWorkerRepository({ query, idFactory = randomUUID, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("A worker-role PostgreSQL query function, ID factory and clock are required.");
  }
  return Object.freeze({
    async claimNext({ workerId }, { signal } = {}) {
      if (!WORKER_ID.test(workerId ?? "")) fail("OUTBOX_CLAIM_INVALID");
      const claimToken = `clm_${idFactory()}`;
      if (!CLAIM_TOKEN.test(claimToken)) fail("OUTBOX_CLAIM_INVALID");
      const result = await query(CLAIM_SQL, [workerId, claimToken, clock().toISOString()], { signal });
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) fail("OUTBOX_SOURCE_INVALID");
      return rowToClaim(result.rows[0]);
    },
    async markSubmitted({ tenantId, eventId, claimToken, ledgerKey, submissionStatus }, { signal } = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !EVENT_ID.test(eventId ?? "")
          || !CLAIM_TOKEN.test(claimToken ?? "") || !LEDGER_KEY.test(ledgerKey ?? "")
          || !SUBMISSION_STATUS.has(submissionStatus)) fail("OUTBOX_CONFIRMATION_INVALID");
      const result = await query(MARK_SUBMITTED_SQL, [
        tenantId, eventId, claimToken, ledgerKey, submissionStatus, clock().toISOString(),
      ], { signal });
      const row = requireQueryResult(result, "OUTBOX_CONFIRMATION_INVALID");
      if (row.event_id !== eventId || row.status !== "submitted" || row.submission_status !== submissionStatus) {
        fail("OUTBOX_CONFIRMATION_INVALID");
      }
      return Object.freeze({ eventId, status: row.status, submissionStatus: row.submission_status });
    },
    async markFailed({ tenantId, eventId, claimToken, failureCode, retryDelaySeconds: retryDelay }, { signal } = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !EVENT_ID.test(eventId ?? "")
          || !CLAIM_TOKEN.test(claimToken ?? "") || !FAILURE_CODE.test(failureCode ?? "")
          || !Number.isSafeInteger(retryDelay) || retryDelay < 1
          || retryDelay > AUDIT_OUTBOX_POLICY.maximumRetryDelaySeconds) fail("OUTBOX_FAILURE_INVALID");
      const result = await query(MARK_FAILED_SQL, [
        tenantId, eventId, claimToken, failureCode, clock().toISOString(), retryDelay,
      ], { signal });
      const row = requireQueryResult(result, "OUTBOX_FAILURE_INVALID");
      if (row.event_id !== eventId || row.status !== "pending") fail("OUTBOX_FAILURE_INVALID");
      return Object.freeze({
        eventId,
        status: row.status,
        nextAttemptAt: asIsoTimestamp(row.next_attempt_at),
      });
    },
  });
}

export function createAuditCommitmentEnqueuer({ enqueue } = {}) {
  if (typeof enqueue !== "function") throw new TypeError("A durable audit enqueue function is required.");
  return Object.freeze({
    async enqueueEvent({ channelName, event }, options) {
      const commitment = buildAuditCommitment({ channelName, event });
      const stored = await enqueue({ channelName, event, commitment }, options);
      if (!stored || stored.eventId !== event.eventId
          || !new Set(["pending", "submitting", "submitted"]).has(stored.status)) {
        fail("OUTBOX_ENQUEUE_INVALID");
      }
      return Object.freeze({
        eventId: stored.eventId,
        status: stored.status,
        ledgerKey: commitment.ledgerKey,
      });
    },
  });
}

export function createAuditOutboxWorker({ workerId, outbox, gateway } = {}) {
  if (!WORKER_ID.test(workerId ?? "")
      || !outbox
      || typeof outbox.claimNext !== "function"
      || typeof outbox.markSubmitted !== "function"
      || typeof outbox.markFailed !== "function"
      || !gateway
      || typeof gateway.submitCommitment !== "function") {
    throw new TypeError("A valid worker ID, outbox repository and Fabric gateway are required.");
  }

  return Object.freeze({
    async runOnce(options) {
      const claim = await outbox.claimNext({ workerId }, options);
      if (claim === null) return Object.freeze({ status: "idle" });
      try {
        const response = await gateway.submitCommitment({
          tenantId: claim.tenantId,
          ledgerValue: claim.ledgerValue,
        });
        if (!response || response.ledgerKey !== claim.ledgerKey || !SUBMISSION_STATUS.has(response.status)) {
          fail("FABRIC_RESPONSE_INVALID");
        }
        const persisted = await outbox.markSubmitted({
          tenantId: claim.tenantId,
          eventId: claim.eventId,
          claimToken: claim.claimToken,
          ledgerKey: response.ledgerKey,
          submissionStatus: response.status,
        }, options);
        return Object.freeze({
          status: "submitted",
          tenantId: claim.tenantId,
          eventId: claim.eventId,
          ledgerKey: claim.ledgerKey,
          submissionStatus: persisted.submissionStatus,
          attemptCount: claim.attemptCount,
        });
      } catch (error) {
        const failureCode = failureCodeFor(error);
        const retryDelay = retryDelaySeconds(claim.attemptCount);
        const failed = await outbox.markFailed({
          tenantId: claim.tenantId,
          eventId: claim.eventId,
          claimToken: claim.claimToken,
          failureCode,
          retryDelaySeconds: retryDelay,
        }, options);
        return Object.freeze({
          status: "retry-scheduled",
          tenantId: claim.tenantId,
          eventId: claim.eventId,
          failureCode,
          nextAttemptAt: failed.nextAttemptAt,
          attemptCount: claim.attemptCount,
        });
      }
    },
  });
}
