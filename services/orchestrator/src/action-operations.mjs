const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const ISSUE_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const ACTION_STATUSES = new Set(["pending", "executing", "succeeded", "failed"]);
const AUDIT_STATUSES = new Set([
  "pending", "submitting", "submitted", "confirming", "committed", "failed",
]);
const SEVERITIES = new Set(["critical", "warning", "info"]);

const SQL = Object.freeze({
  recover: "SELECT * FROM orchestration.recover_expired_security_action_leases($1,$2)",
  issues: "SELECT * FROM orchestration.list_security_action_operational_issues($1,$2)",
});

export const SECURITY_ACTION_OPERATIONS_POLICY = Object.freeze({
  actionLeaseSeconds: 300,
  stuckPendingSeconds: 300,
  auditDeliveryRequiredForHealthy: true,
  maximumIssuePageSize: 500,
});

export class SecurityActionOperationsError extends Error {
  constructor(reasonCode, options) {
    super("Security-action operations state could not be loaded.", options);
    this.name = "SecurityActionOperationsError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new SecurityActionOperationsError(
    reasonCode,
    cause === undefined ? undefined : { cause },
  );
}

function iso(value) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) fail("SECURITY_ACTION_OPERATIONS_SOURCE_INVALID");
  return parsed.toISOString();
}

function nullableIso(value) {
  return value === null || value === undefined || value === "infinity" || value === Infinity
    ? null
    : iso(value);
}

function mapIssue(row) {
  const issue = {
    tenantId: row?.tenant_id,
    actionId: row?.action_id,
    correlationId: row?.correlation_id,
    issueCode: row?.issue_code,
    severity: row?.severity,
    actionStatus: row?.action_status,
    attemptCount: Number(row?.attempt_count),
    lastFailureCode: row?.last_failure_code ?? null,
    nextAttemptAt: nullableIso(row?.next_attempt_at),
    leaseExpiresAt: nullableIso(row?.lease_expires_at),
    auditEventId: row?.audit_event_id ?? null,
    auditDeliveryStatus: row?.audit_delivery_status ?? null,
    retryable: row?.retryable,
    observedAt: iso(row?.observed_at),
  };
  if (!TENANT_ID.test(issue.tenantId ?? "")
    || !ACTION_ID.test(issue.actionId ?? "")
    || !CORRELATION_ID.test(issue.correlationId ?? "")
    || !ISSUE_CODE.test(issue.issueCode ?? "")
    || !SEVERITIES.has(issue.severity)
    || !ACTION_STATUSES.has(issue.actionStatus)
    || !Number.isSafeInteger(issue.attemptCount)
    || issue.attemptCount < 0
    || (issue.lastFailureCode !== null && !REASON_CODE.test(issue.lastFailureCode))
    || (issue.auditEventId !== null && !EVENT_ID.test(issue.auditEventId))
    || (issue.auditDeliveryStatus !== null
      && !AUDIT_STATUSES.has(issue.auditDeliveryStatus))
    || typeof issue.retryable !== "boolean") {
    fail("SECURITY_ACTION_OPERATIONS_SOURCE_INVALID");
  }
  return Object.freeze(issue);
}

export function createPostgresSecurityActionOperationsRepository({
  query,
  clock = () => new Date(),
} = {}) {
  if (typeof query !== "function" || typeof clock !== "function") {
    throw new TypeError("An operator-role PostgreSQL query function and clock are required.");
  }
  const now = () => iso(clock());
  return Object.freeze({
    async recoverExpiredLeases({ workerId }, options = {}) {
      if (!WORKER_ID.test(workerId ?? "")) fail("SECURITY_ACTION_RECOVERY_INVALID");
      const result = await query(SQL.recover, [workerId, now()], options);
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
        fail("SECURITY_ACTION_RECOVERY_INVALID");
      }
      const recoveredCount = Number(result.rows[0].recovered_count);
      if (!Number.isSafeInteger(recoveredCount) || recoveredCount < 0) {
        fail("SECURITY_ACTION_RECOVERY_INVALID");
      }
      return Object.freeze({
        recoveredCount,
        earliestRetryAt: nullableIso(result.rows[0].earliest_retry_at),
      });
    },

    async listIssues({ limit = 100 } = {}, options = {}) {
      if (!Number.isSafeInteger(limit)
        || limit < 1
        || limit > SECURITY_ACTION_OPERATIONS_POLICY.maximumIssuePageSize) {
        fail("SECURITY_ACTION_OPERATIONS_QUERY_INVALID");
      }
      const result = await query(SQL.issues, [limit, now()], options);
      if (!result || !Array.isArray(result.rows)) {
        fail("SECURITY_ACTION_OPERATIONS_SOURCE_INVALID");
      }
      return Object.freeze(result.rows.map(mapIssue));
    },
  });
}

function summarize(issues) {
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const issue of issues) counts[issue.severity] += 1;
  return Object.freeze(counts);
}

export function createSecurityActionOperationsMonitor({ repository } = {}) {
  if (!repository
    || typeof repository.recoverExpiredLeases !== "function"
    || typeof repository.listIssues !== "function") {
    throw new TypeError("A security-action operations repository is required.");
  }
  const inspect = async ({ limit = 100 } = {}, options = {}) => {
    const issues = await repository.listIssues({ limit }, options);
    const counts = summarize(issues);
    return Object.freeze({
      status: counts.critical > 0 ? "critical" : issues.length > 0 ? "attention" : "healthy",
      counts,
      issues,
    });
  };
  return Object.freeze({
    inspect,
    async recoverOnStartup({ workerId, limit = 100 }, options = {}) {
      const recovery = await repository.recoverExpiredLeases({ workerId }, options);
      const report = await inspect({ limit }, options);
      return Object.freeze({ recovery, ...report });
    },
  });
}
