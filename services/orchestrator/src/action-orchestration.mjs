import { randomUUID } from "node:crypto";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DECISION_ID = /^dec_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CLAIM_TOKEN = /^clm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const EXTERNAL_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/u;
const ACTION_TYPES = new Set([
  "restrict-access",
  "suspend-subject",
  "block-renewal",
  "revoke-certificate",
  "restore-access",
  "issue-replacement-certificate",
]);
const SEVERITY_ACTION_TYPES = new Set(["block-renewal", "revoke-certificate"]);
const EXECUTION_STATUSES = new Set(["pending", "executing", "succeeded", "failed"]);
const AUTHORITY_CLASSES = new Set(["policy-quarantine", "severity-rule", "recovery-authorization"]);
const SQL = Object.freeze({
  enqueueSeverity: "SELECT * FROM orchestration.enqueue_severity_security_action($1,$2,$3,$4,$5,$6,$7,$8,$9)",
  claimNext: "SELECT * FROM orchestration.claim_security_action($1,$2,$3)",
  markSucceeded: "SELECT * FROM orchestration.mark_security_action_succeeded($1,$2,$3,$4::jsonb,$5,$6)",
  markFailed: "SELECT * FROM orchestration.mark_security_action_failed($1,$2,$3,$4,$5,$6)",
  getStatus: "SELECT * FROM orchestration.get_security_action_status($1,$2)",
});

export const SECURITY_ACTION_ORCHESTRATION_POLICY = Object.freeze({
  claimLeaseSeconds: 300,
  initialRetryDelaySeconds: 5,
  maximumRetryDelaySeconds: 600,
  delivery: "at-least-once-with-stable-action-id",
  sourceRequest: "append-only-authorized-action",
});

export class SecurityActionOrchestrationError extends Error {
  constructor(reasonCode, options) {
    super("The security action could not be orchestrated.", options);
    this.name = "SecurityActionOrchestrationError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new SecurityActionOrchestrationError(
    reasonCode,
    cause === undefined ? undefined : { cause },
  );
}

function one(result, reasonCode) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail(reasonCode);
  return result.rows[0];
}

function maybeOne(result, reasonCode) {
  if (!result || !Array.isArray(result.rows) || result.rows.length > 1) fail(reasonCode);
  return result.rows[0] ?? null;
}

function iso(value, reasonCode = "SECURITY_ACTION_SOURCE_INVALID") {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) fail(reasonCode);
  return timestamp.toISOString();
}

function claimToken(idFactory) {
  const value = `clm_${idFactory()}`;
  if (!CLAIM_TOKEN.test(value)) fail("SECURITY_ACTION_CLAIM_INVALID");
  return value;
}

function retryDelay(attemptCount) {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) {
    fail("SECURITY_ACTION_SOURCE_INVALID");
  }
  return Math.min(
    SECURITY_ACTION_ORCHESTRATION_POLICY.maximumRetryDelaySeconds,
    SECURITY_ACTION_ORCHESTRATION_POLICY.initialRetryDelaySeconds
      * (2 ** Math.min(attemptCount - 1, 30)),
  );
}

function failureCode(error, fallback = "ACTION_EXECUTION_FAILED") {
  const code = error && typeof error === "object" ? error.reasonCode : undefined;
  return REASON_CODE.test(code ?? "") ? code : fallback;
}

function validateActionIdentity(value, requireClaim = false) {
  if (!TENANT_ID.test(value.tenantId ?? "")
    || !ACTION_ID.test(value.actionId ?? "")
    || (requireClaim && !CLAIM_TOKEN.test(value.claimToken ?? ""))) {
    fail("SECURITY_ACTION_SOURCE_INVALID");
  }
}

function mapState(row) {
  return Object.freeze({
    access: row.access_state,
    renewal: row.renewal_state,
    targetCertificate: row.target_certificate_state,
    replacement: row.replacement_state,
  });
}

function mapClaim(row) {
  if (!row) return null;
  const claim = {
    tenantId: row.tenant_id,
    actionId: row.action_id,
    decisionId: row.decision_id,
    correlationId: row.correlation_id,
    targetSubjectId: row.target_subject_id,
    targetCertificateId: row.target_certificate_id,
    actionType: row.action_type,
    authorityClass: row.authority_class,
    reasonCode: row.reason_code,
    triggerContextHashSha256: row.trigger_context_hash_sha256,
    claimToken: row.claim_token,
    attemptCount: Number(row.attempt_count),
    expectedStateVersion: Number(row.expected_state_version),
    currentState: mapState(row),
  };
  validateActionIdentity(claim, true);
  if (!DECISION_ID.test(claim.decisionId ?? "")
    || !CORRELATION_ID.test(claim.correlationId ?? "")
    || !SUBJECT_ID.test(claim.targetSubjectId ?? "")
    || !CERTIFICATE_ID.test(claim.targetCertificateId ?? "")
    || !ACTION_TYPES.has(claim.actionType)
    || !AUTHORITY_CLASSES.has(claim.authorityClass)
    || !REASON_CODE.test(claim.reasonCode ?? "")
    || !SHA256.test(claim.triggerContextHashSha256 ?? "")
    || !Number.isSafeInteger(claim.attemptCount)
    || claim.attemptCount < 1
    || !Number.isSafeInteger(claim.expectedStateVersion)
    || claim.expectedStateVersion < 1) {
    fail("SECURITY_ACTION_SOURCE_INVALID");
  }
  return Object.freeze(claim);
}

function mapStatus(row) {
  if (!row) return null;
  const status = {
    tenantId: row.tenant_id,
    actionId: row.action_id,
    status: row.status,
    attemptCount: Number(row.attempt_count),
    lastFailureCode: row.last_failure_code,
    nextAttemptAt: row.next_attempt_at ? iso(row.next_attempt_at) : null,
    succeededAt: row.succeeded_at ? iso(row.succeeded_at) : null,
  };
  validateActionIdentity(status);
  if (!EXECUTION_STATUSES.has(status.status)
    || !Number.isSafeInteger(status.attemptCount)
    || status.attemptCount < 0
    || (status.lastFailureCode !== null && !REASON_CODE.test(status.lastFailureCode ?? ""))) {
    fail("SECURITY_ACTION_STATUS_INVALID");
  }
  return Object.freeze(status);
}

export function createPostgresSecurityActionRepository({
  query,
  idFactory = randomUUID,
  clock = () => new Date(),
} = {}) {
  if (typeof query !== "function" || typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("A PostgreSQL query function, ID factory and clock are required.");
  }
  const now = () => iso(clock(), "SECURITY_ACTION_TIME_INVALID");
  return Object.freeze({
    async enqueueSeverityAction(value, options = {}) {
      if (!TENANT_ID.test(value?.tenantId ?? "")
        || !ACTION_ID.test(value?.actionId ?? "")
        || !DECISION_ID.test(value?.decisionId ?? "")
        || !SUBJECT_ID.test(value?.targetSubjectId ?? "")
        || !CERTIFICATE_ID.test(value?.targetCertificateId ?? "")
        || !SEVERITY_ACTION_TYPES.has(value?.actionType)
        || !REASON_CODE.test(value?.reasonCode ?? "")
        || !SHA256.test(value?.triggerContextHashSha256 ?? "")) {
        fail("SECURITY_ACTION_REQUEST_INVALID");
      }
      const row = one(await query(SQL.enqueueSeverity, [
        value.tenantId,
        value.actionId,
        value.decisionId,
        value.targetSubjectId,
        value.targetCertificateId,
        value.actionType,
        value.reasonCode,
        value.triggerContextHashSha256,
        now(),
      ], options), "SECURITY_ACTION_REQUEST_INVALID");
      const status = mapStatus(row);
      if (status.status !== "pending" && status.status !== "failed") {
        fail("SECURITY_ACTION_REQUEST_INVALID");
      }
      return status;
    },

    async claimNext({ workerId }, options = {}) {
      if (!WORKER_ID.test(workerId ?? "")) fail("SECURITY_ACTION_CLAIM_INVALID");
      return mapClaim(maybeOne(await query(
        SQL.claimNext,
        [workerId, claimToken(idFactory), now()],
        options,
      ), "SECURITY_ACTION_SOURCE_INVALID"));
    },

    async markSucceeded(value, options = {}) {
      validateActionIdentity(value, true);
      if (!Number.isSafeInteger(value.expectedStateVersion)
        || value.expectedStateVersion < 1
        || (value.externalReference !== null
          && !EXTERNAL_REFERENCE.test(value.externalReference ?? ""))) {
        fail("SECURITY_ACTION_SUCCESS_INVALID");
      }
      const row = one(await query(SQL.markSucceeded, [
        value.tenantId,
        value.actionId,
        value.claimToken,
        JSON.stringify(value.resultState),
        value.externalReference,
        now(),
      ], options), "SECURITY_ACTION_SUCCESS_INVALID");
      const status = mapStatus(row);
      if (status.status !== "succeeded") fail("SECURITY_ACTION_SUCCESS_INVALID");
      return status;
    },

    async markFailed(value, options = {}) {
      validateActionIdentity(value, true);
      if (!REASON_CODE.test(value.failureCode ?? "")
        || !Number.isSafeInteger(value.retryDelaySeconds)
        || value.retryDelaySeconds < 1
        || value.retryDelaySeconds
          > SECURITY_ACTION_ORCHESTRATION_POLICY.maximumRetryDelaySeconds) {
        fail("SECURITY_ACTION_FAILURE_INVALID");
      }
      const row = one(await query(SQL.markFailed, [
        value.tenantId,
        value.actionId,
        value.claimToken,
        value.failureCode,
        now(),
        value.retryDelaySeconds,
      ], options), "SECURITY_ACTION_FAILURE_INVALID");
      const status = mapStatus(row);
      if (status.status !== "failed") fail("SECURITY_ACTION_FAILURE_INVALID");
      return status;
    },

    async getStatus({ tenantId, actionId }, options = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !ACTION_ID.test(actionId ?? "")) {
        fail("SECURITY_ACTION_STATUS_INVALID");
      }
      return mapStatus(maybeOne(
        await query(SQL.getStatus, [tenantId, actionId], options),
        "SECURITY_ACTION_STATUS_INVALID",
      ));
    },
  });
}

export function createSecurityActionExecutor({ revokeCertificate } = {}) {
  if (revokeCertificate !== undefined && typeof revokeCertificate !== "function") {
    throw new TypeError("The optional certificate revocation executor must be a function.");
  }
  return Object.freeze({
    async execute(action, options) {
      if (!action || !ACTION_TYPES.has(action.actionType) || !ACTION_ID.test(action.actionId ?? "")) {
        fail("SECURITY_ACTION_EXECUTION_INVALID");
      }
      if (["restrict-access", "suspend-subject", "block-renewal"].includes(action.actionType)) {
        return Object.freeze({
          actionId: action.actionId,
          status: "succeeded",
          externalReference: null,
        });
      }
      if (action.actionType === "revoke-certificate") {
        if (!revokeCertificate) fail("REVOCATION_EXECUTOR_UNAVAILABLE");
        const result = await revokeCertificate(action, options);
        if (!result
          || result.certificateId !== action.targetCertificateId
          || result.state !== "revoked"
          || !EXTERNAL_REFERENCE.test(result.eventId ?? "")) {
          fail("REVOCATION_EXECUTION_UNCONFIRMED");
        }
        return Object.freeze({
          actionId: action.actionId,
          status: "succeeded",
          externalReference: result.eventId,
        });
      }
      fail("RECOVERY_EXECUTION_NOT_GOVERNED");
    },
  });
}

export function createSecurityActionWorker({
  workerId,
  repository,
  executor,
  transitionState,
} = {}) {
  if (!WORKER_ID.test(workerId ?? "")
    || !repository
    || ["claimNext", "markSucceeded", "markFailed"].some(
      (name) => typeof repository[name] !== "function",
    )
    || !executor
    || typeof executor.execute !== "function"
    || typeof transitionState !== "function") {
    throw new TypeError("A valid worker, repository, executor and state transition are required.");
  }
  return Object.freeze({
    async runOnce(options) {
      const claim = await repository.claimNext({ workerId }, options);
      if (!claim) return Object.freeze({ status: "idle" });
      try {
        const transition = transitionState({
          currentState: claim.currentState,
          actionType: claim.actionType,
        });
        const confirmation = await executor.execute(Object.freeze({
          ...claim,
          nextState: transition.state,
          changed: transition.changed,
        }), options);
        if (!confirmation
          || confirmation.actionId !== claim.actionId
          || confirmation.status !== "succeeded"
          || (confirmation.externalReference !== null
            && !EXTERNAL_REFERENCE.test(confirmation.externalReference ?? ""))) {
          fail("SECURITY_ACTION_EXECUTION_UNCONFIRMED");
        }
        const stored = await repository.markSucceeded({
          ...claim,
          resultState: transition.state,
          externalReference: confirmation.externalReference,
        }, options);
        return Object.freeze({
          status: stored.status,
          tenantId: claim.tenantId,
          actionId: claim.actionId,
          actionType: claim.actionType,
          attemptCount: claim.attemptCount,
          changed: transition.changed,
          state: transition.state,
          externalReference: confirmation.externalReference,
        });
      } catch (error) {
        const code = failureCode(error);
        const stored = await repository.markFailed({
          ...claim,
          failureCode: code,
          retryDelaySeconds: retryDelay(claim.attemptCount),
        }, options);
        return Object.freeze({
          status: stored.status,
          tenantId: claim.tenantId,
          actionId: claim.actionId,
          actionType: claim.actionType,
          attemptCount: claim.attemptCount,
          failureCode: code,
          nextAttemptAt: stored.nextAttemptAt,
        });
      }
    },
  });
}
