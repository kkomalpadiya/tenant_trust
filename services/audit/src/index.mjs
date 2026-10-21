import { randomUUID } from "node:crypto";
import { assertAuditLedgerValue, buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CLAIM_TOKEN = /^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const FAILURE_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const LEDGER_KEY = /^audit~[a-z]+(?:-[a-z]+)*~[0-9a-f]{64}$/u;
const SUBMISSION_STATUS = new Set(["created", "duplicate"]);
const OUTBOX_STATES = new Set(["pending", "submitting", "submitted", "confirming", "committed", "failed"]);
const SQL = Object.freeze({
  enqueue: `SELECT * FROM audit.enqueue_fabric_commitment($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11::jsonb,$12)`,
  claimSubmission: "SELECT * FROM audit.claim_fabric_commitment($1,$2,$3)",
  claimConfirmation: "SELECT * FROM audit.claim_fabric_commitment_confirmation($1,$2,$3)",
  recordSubmission: "SELECT * FROM audit.record_fabric_commitment_submission($1,$2,$3,$4,$5,$6,$7)",
  markCommitted: "SELECT * FROM audit.mark_fabric_commitment_committed($1,$2,$3,$4,$5,$6,$7,$8)",
  markCommitFailed: "SELECT * FROM audit.mark_fabric_commitment_commit_failed($1,$2,$3,$4,$5,$6,$7,$8,$9)",
  markConfirmationPending: "SELECT * FROM audit.mark_fabric_commitment_confirmation_pending($1,$2,$3,$4,$5,$6,$7)",
  markSubmissionFailed: "SELECT * FROM audit.mark_fabric_commitment_failed($1,$2,$3,$4,$5,$6)",
  summary: "SELECT * FROM audit.get_fabric_commitment_delivery_summary()",
  gaps: "SELECT * FROM audit.list_fabric_commitment_gaps($1)",
});

export const AUDIT_OUTBOX_POLICY = Object.freeze({ claimLeaseSeconds: 300, initialRetryDelaySeconds: 5,
  maximumRetryDelaySeconds: 600, delivery: "at-least-once-with-commit-reconciliation" });

export class AuditOutboxError extends Error {
  constructor(reasonCode, options) {
    super("The asynchronous audit operation failed.", options);
    this.name = "AuditOutboxError";
    this.reasonCode = reasonCode;
  }
}
function fail(reasonCode, cause) { throw new AuditOutboxError(reasonCode, cause === undefined ? undefined : { cause }); }
function one(result, reasonCode) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail(reasonCode);
  return result.rows[0];
}
function maybeOne(result) {
  if (!result || !Array.isArray(result.rows) || result.rows.length > 1) fail("OUTBOX_SOURCE_INVALID");
  return result.rows[0] ?? null;
}
function iso(value, reasonCode = "OUTBOX_SOURCE_INVALID") {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) fail(reasonCode);
  return timestamp.toISOString();
}
function delayFor(attemptCount) {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) fail("OUTBOX_SOURCE_INVALID");
  return Math.min(600, 5 * (2 ** Math.min(attemptCount - 1, 30)));
}
function failureCodeFor(error, fallback) {
  const code = error && typeof error === "object" ? error.reasonCode : undefined;
  return FAILURE_CODE.test(code ?? "") ? code : fallback;
}
function token(idFactory) {
  const value = `clm_${idFactory()}`;
  if (!CLAIM_TOKEN.test(value)) fail("OUTBOX_CLAIM_INVALID");
  return value;
}
function validateIdentity(value) {
  if (!TENANT_ID.test(value.tenantId ?? "") || !EVENT_ID.test(value.eventId ?? "")
      || !CLAIM_TOKEN.test(value.claimToken ?? "")) fail("OUTBOX_SOURCE_INVALID");
}
function submissionClaim(row) {
  if (!row) return null;
  const value = { tenantId: row.tenant_id, eventId: row.event_id, channelName: row.channel_name,
    event: row.event_document, canonicalPreimageJson: row.canonical_preimage_json, ledgerKey: row.ledger_key,
    ledgerValue: row.ledger_value, claimToken: row.claim_token, attemptCount: Number(row.attempt_count) };
  validateIdentity(value);
  if (!LEDGER_KEY.test(value.ledgerKey ?? "") || !Number.isSafeInteger(value.attemptCount) || value.attemptCount < 1) fail("OUTBOX_SOURCE_INVALID");
  assertAuditLedgerValue(value.ledgerValue);
  if (value.ledgerKey !== `audit~${value.ledgerValue.recordType}~${value.ledgerValue.eventKeyHashSha256}`) fail("OUTBOX_SOURCE_INVALID");
  return Object.freeze({ ...value, event: Object.freeze(structuredClone(value.event)),
    ledgerValue: Object.freeze(structuredClone(value.ledgerValue)) });
}
function confirmationClaim(row) {
  if (!row) return null;
  const value = { tenantId: row.tenant_id, eventId: row.event_id, transactionId: row.transaction_id,
    claimToken: row.claim_token, attemptCount: Number(row.attempt_count) };
  validateIdentity(value);
  if (!SHA256.test(value.transactionId ?? "") || !Number.isSafeInteger(value.attemptCount) || value.attemptCount < 1) fail("OUTBOX_SOURCE_INVALID");
  return Object.freeze(value);
}
function validateStatus(status, transactionId) {
  const validationCode = Number(status?.validationCode);
  const blockNumber = Number(status?.blockNumber);
  if (status?.transactionId !== transactionId || !Number.isSafeInteger(validationCode) || validationCode < 0
      || !Number.isSafeInteger(blockNumber) || blockNumber < 0 || !new Set(["gateway-status", "qscc"]).has(status?.source)) {
    fail("FABRIC_COMMIT_STATUS_INVALID");
  }
  return { transactionId, validationCode, blockNumber, source: status.source, successful: validationCode === 0 };
}

export function createPostgresAuditOutboxEnqueueRepository({ query, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof clock !== "function") throw new TypeError("A transaction-bound PostgreSQL query function and clock are required.");
  return Object.freeze({ async enqueue({ channelName, event, commitment }, { signal } = {}) {
    const result = await query(SQL.enqueue, [event.tenantId,event.eventId,channelName,event.eventType,
      commitment.ledgerValue.recordType,JSON.stringify(event),commitment.canonicalPreimageJson,commitment.ledgerKey,
      commitment.ledgerValue.eventKeyHashSha256,commitment.ledgerValue.commitmentHashSha256,
      JSON.stringify(commitment.ledgerValue),clock().toISOString()], { signal });
    const row = one(result, "OUTBOX_ENQUEUE_INVALID");
    if (row.event_id !== event.eventId || !OUTBOX_STATES.has(row.status)
        || row.event_key_hash_sha256 !== commitment.ledgerValue.eventKeyHashSha256
        || row.commitment_hash_sha256 !== commitment.ledgerValue.commitmentHashSha256) fail("OUTBOX_ENQUEUE_INVALID");
    return Object.freeze({ eventId: row.event_id, status: row.status });
  } });
}

export function createPostgresAuditOutboxWorkerRepository({ query, idFactory = randomUUID, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("A worker-role PostgreSQL query function, ID factory and clock are required.");
  }
  const now = () => clock().toISOString();
  const execute = (sql, values, options) => query(sql, values, options);
  return Object.freeze({
    async claimNext({ workerId }, options = {}) {
      if (!WORKER_ID.test(workerId ?? "")) fail("OUTBOX_CLAIM_INVALID");
      return submissionClaim(maybeOne(await execute(SQL.claimSubmission, [workerId,token(idFactory),now()], options)));
    },
    async claimConfirmation({ workerId }, options = {}) {
      if (!WORKER_ID.test(workerId ?? "")) fail("OUTBOX_CLAIM_INVALID");
      return confirmationClaim(maybeOne(await execute(SQL.claimConfirmation, [workerId,token(idFactory),now()], options)));
    },
    async recordSubmission(value, options = {}) {
      validateIdentity(value);
      if (!LEDGER_KEY.test(value.ledgerKey ?? "") || !SUBMISSION_STATUS.has(value.submissionStatus) || !SHA256.test(value.transactionId ?? "")) fail("OUTBOX_SUBMISSION_INVALID");
      const row = one(await execute(SQL.recordSubmission, [value.tenantId,value.eventId,value.claimToken,value.ledgerKey,
        value.submissionStatus,value.transactionId,now()], options), "OUTBOX_SUBMISSION_INVALID");
      if (row.status !== "confirming" || row.transaction_id !== value.transactionId) fail("OUTBOX_SUBMISSION_INVALID");
      return Object.freeze({ eventId: row.event_id, status: row.status, transactionId: row.transaction_id });
    },
    async markCommitted(value, options = {}) {
      validateIdentity(value);
      const row = one(await execute(SQL.markCommitted, [value.tenantId,value.eventId,value.claimToken,value.transactionId,
        value.validationCode,value.blockNumber,value.confirmationSource,now()], options), "OUTBOX_CONFIRMATION_INVALID");
      if (row.status !== "committed") fail("OUTBOX_CONFIRMATION_INVALID");
      return Object.freeze({ eventId: row.event_id, status: row.status, blockNumber: String(row.block_number) });
    },
    async markCommitFailed(value, options = {}) {
      validateIdentity(value);
      const row = one(await execute(SQL.markCommitFailed, [value.tenantId,value.eventId,value.claimToken,value.transactionId,
        value.validationCode,value.blockNumber,value.confirmationSource,now(),value.retryDelaySeconds], options), "OUTBOX_FAILURE_INVALID");
      if (row.status !== "failed") fail("OUTBOX_FAILURE_INVALID");
      return Object.freeze({ eventId: row.event_id, status: row.status, nextAttemptAt: iso(row.next_attempt_at) });
    },
    async markConfirmationPending(value, options = {}) {
      validateIdentity(value);
      const row = one(await execute(SQL.markConfirmationPending, [value.tenantId,value.eventId,value.claimToken,
        value.transactionId,value.failureCode,now(),value.retryDelaySeconds], options), "OUTBOX_CONFIRMATION_INVALID");
      if (row.status !== "submitted") fail("OUTBOX_CONFIRMATION_INVALID");
      return Object.freeze({ eventId: row.event_id, status: row.status, nextConfirmationAt: iso(row.next_confirmation_at) });
    },
    async markFailed(value, options = {}) {
      validateIdentity(value);
      const row = one(await execute(SQL.markSubmissionFailed, [value.tenantId,value.eventId,value.claimToken,
        value.failureCode,now(),value.retryDelaySeconds], options), "OUTBOX_FAILURE_INVALID");
      if (row.status !== "failed") fail("OUTBOX_FAILURE_INVALID");
      return Object.freeze({ eventId: row.event_id, status: row.status, nextAttemptAt: iso(row.next_attempt_at) });
    },
    async deliveryStatus({ limit = 100 } = {}, options = {}) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new TypeError("limit must be between 1 and 500.");
      const [summary,gaps] = await Promise.all([execute(SQL.summary, [], options),execute(SQL.gaps, [limit], options)]);
      if (!Array.isArray(summary?.rows) || !Array.isArray(gaps?.rows)) fail("OUTBOX_STATUS_INVALID");
      return Object.freeze({ summary: summary.rows.map((row) => Object.freeze({ status: row.status,eventCount: Number(row.event_count),
        oldestEventAt: row.oldest_event_at ? iso(row.oldest_event_at) : null })), gaps: gaps.rows.map((row) => Object.freeze({
        tenantId: row.tenant_id,eventId: row.event_id,status: row.status,attemptCount: Number(row.attempt_count),
        transactionId: row.transaction_id,lastFailureCode: row.last_failure_code,updatedAt: iso(row.updated_at) })) });
    },
  });
}

export function createAuditCommitmentEnqueuer({ enqueue } = {}) {
  if (typeof enqueue !== "function") throw new TypeError("A durable audit enqueue function is required.");
  return Object.freeze({ async enqueueEvent({ channelName,event }, options) {
    const commitment = buildAuditCommitment({ channelName,event });
    const stored = await enqueue({ channelName,event,commitment }, options);
    if (!stored || stored.eventId !== event.eventId || !OUTBOX_STATES.has(stored.status)) fail("OUTBOX_ENQUEUE_INVALID");
    return Object.freeze({ eventId: stored.eventId,status: stored.status,ledgerKey: commitment.ledgerKey });
  } });
}

async function finishConfirmation({ claim,status,outbox,options }) {
  const checked = validateStatus(status, claim.transactionId);
  const common = { tenantId: claim.tenantId,eventId: claim.eventId,claimToken: claim.claimToken,
    transactionId: claim.transactionId,validationCode: checked.validationCode,blockNumber: checked.blockNumber,
    confirmationSource: checked.source };
  if (checked.successful) {
    await outbox.markCommitted(common, options);
    return Object.freeze({ status: "committed",tenantId: claim.tenantId,eventId: claim.eventId,
      transactionId: claim.transactionId,blockNumber: String(checked.blockNumber),confirmationSource: checked.source });
  }
  const failed = await outbox.markCommitFailed({ ...common,retryDelaySeconds: delayFor(claim.attemptCount) }, options);
  return Object.freeze({ status: "failed",tenantId: claim.tenantId,eventId: claim.eventId,
    transactionId: claim.transactionId,validationCode: checked.validationCode,nextAttemptAt: failed.nextAttemptAt });
}

export function createAuditOutboxWorker({ workerId,outbox,gateway } = {}) {
  const required = ["claimNext","claimConfirmation","recordSubmission","markCommitted","markCommitFailed","markConfirmationPending","markFailed"];
  if (!WORKER_ID.test(workerId ?? "") || !outbox || required.some((name) => typeof outbox[name] !== "function")
      || !gateway || typeof gateway.submitCommitment !== "function" || typeof gateway.queryTransactionStatus !== "function") {
    throw new TypeError("A valid worker ID, reconciliation repository and Fabric gateway are required.");
  }
  return Object.freeze({ async runOnce(options) {
    const gap = await outbox.claimConfirmation({ workerId }, options);
    if (gap) {
      try {
        const status = await gateway.queryTransactionStatus({ tenantId: gap.tenantId,transactionId: gap.transactionId });
        return await finishConfirmation({ claim: gap,status,outbox,options });
      } catch (error) {
        const failureCode = failureCodeFor(error, "TRANSACTION_STATUS_QUERY_FAILED");
        const pending = await outbox.markConfirmationPending({ ...gap,failureCode,retryDelaySeconds: delayFor(gap.attemptCount) }, options);
        return Object.freeze({ status: "confirmation-pending",tenantId: gap.tenantId,eventId: gap.eventId,
          transactionId: gap.transactionId,failureCode,nextConfirmationAt: pending.nextConfirmationAt });
      }
    }
    const claim = await outbox.claimNext({ workerId }, options);
    if (!claim) return Object.freeze({ status: "idle" });
    let submitted;
    try {
      submitted = await gateway.submitCommitment({ tenantId: claim.tenantId,ledgerValue: claim.ledgerValue });
      if (!submitted || submitted.ledgerKey !== claim.ledgerKey || !SUBMISSION_STATUS.has(submitted.status)
          || !SHA256.test(submitted.transactionId ?? "") || typeof submitted.waitForCommit !== "function") fail("FABRIC_RESPONSE_INVALID");
      await outbox.recordSubmission({ tenantId: claim.tenantId,eventId: claim.eventId,claimToken: claim.claimToken,
        ledgerKey: claim.ledgerKey,submissionStatus: submitted.status,transactionId: submitted.transactionId }, options);
    } catch (error) {
      const failureCode = failureCodeFor(error, "FABRIC_SUBMISSION_FAILED");
      const failed = await outbox.markFailed({ ...claim,failureCode,retryDelaySeconds: delayFor(claim.attemptCount) }, options);
      return Object.freeze({ status: "failed",tenantId: claim.tenantId,eventId: claim.eventId,
        failureCode,nextAttemptAt: failed.nextAttemptAt,attemptCount: claim.attemptCount });
    }
    const active = { ...claim,transactionId: submitted.transactionId };
    try {
      return await finishConfirmation({ claim: active,status: await submitted.waitForCommit(),outbox,options });
    } catch (error) {
      const failureCode = failureCodeFor(error, "COMMIT_STATUS_UNAVAILABLE");
      const pending = await outbox.markConfirmationPending({ ...active,failureCode,retryDelaySeconds: delayFor(claim.attemptCount) }, options);
      return Object.freeze({ status: "confirmation-pending",tenantId: claim.tenantId,eventId: claim.eventId,
        transactionId: submitted.transactionId,failureCode,nextConfirmationAt: pending.nextConfirmationAt });
    }
  } });
}
