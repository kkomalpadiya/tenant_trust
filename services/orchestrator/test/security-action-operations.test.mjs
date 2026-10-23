import assert from "node:assert/strict";
import test from "node:test";

import {
  SecurityActionOperationsError,
  createPostgresSecurityActionOperationsRepository,
  createSecurityActionOperationsMonitor,
} from "../src/index.mjs";

const observedAt = "2026-10-23T10:00:00.000Z";
const issueRow = Object.freeze({
  tenant_id: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  action_id: "act_018f1234-5678-7abc-8def-0123456789ac",
  correlation_id: "cor_018f1234-5678-7abc-8def-0123456789ad",
  issue_code: "ACTION_AUDIT_DELIVERY_FAILED",
  severity: "critical",
  action_status: "succeeded",
  attempt_count: 2,
  last_failure_code: null,
  next_attempt_at: "2026-10-23T09:59:00.000Z",
  lease_expires_at: null,
  audit_event_id: "evt_018f1234-5678-7abc-8def-0123456789ae",
  audit_delivery_status: "failed",
  retryable: true,
  observed_at: observedAt,
});

test("operator repository recovers expired leases without inventing action state", async () => {
  const calls = [];
  const repository = createPostgresSecurityActionOperationsRepository({
    clock: () => new Date(observedAt),
    query: async (sql, values) => {
      calls.push({ sql, values });
      return { rows: [{ recovered_count: 2, earliest_retry_at: observedAt }] };
    },
  });

  const recovered = await repository.recoverExpiredLeases({
    workerId: "orchestrator.restart-1",
  });
  assert.deepEqual(recovered, { recoveredCount: 2, earliestRetryAt: observedAt });
  assert.match(calls[0].sql, /recover_expired_security_action_leases/u);
  assert.deepEqual(calls[0].values, ["orchestrator.restart-1", observedAt]);
});

test("monitor keeps audit delivery failures visible after action success", async () => {
  const repository = createPostgresSecurityActionOperationsRepository({
    clock: () => new Date(observedAt),
    query: async (sql) => {
      assert.match(sql, /list_security_action_operational_issues/u);
      return { rows: [issueRow] };
    },
  });
  const report = await createSecurityActionOperationsMonitor({ repository }).inspect();

  assert.equal(report.status, "critical");
  assert.deepEqual(report.counts, { critical: 1, warning: 0, info: 0 });
  assert.equal(report.issues[0].actionStatus, "succeeded");
  assert.equal(report.issues[0].issueCode, "ACTION_AUDIT_DELIVERY_FAILED");
  assert.equal(report.issues[0].auditDeliveryStatus, "failed");
});

test("startup recovery runs before the persisted operations report", async () => {
  const calls = [];
  const monitor = createSecurityActionOperationsMonitor({
    repository: {
      async recoverExpiredLeases(value) {
        calls.push(["recover", value]);
        return { recoveredCount: 1, earliestRetryAt: observedAt };
      },
      async listIssues(value) {
        calls.push(["inspect", value]);
        return [];
      },
    },
  });

  const report = await monitor.recoverOnStartup({
    workerId: "orchestrator.restart-2",
    limit: 50,
  });
  assert.deepEqual(calls, [
    ["recover", { workerId: "orchestrator.restart-2" }],
    ["inspect", { limit: 50 }],
  ]);
  assert.equal(report.recovery.recoveredCount, 1);
  assert.equal(report.status, "healthy");
});

test("malformed operational rows fail closed", async () => {
  const repository = createPostgresSecurityActionOperationsRepository({
    clock: () => new Date(observedAt),
    query: async () => ({ rows: [{ ...issueRow, retryable: "yes" }] }),
  });
  await assert.rejects(
    repository.listIssues(),
    (error) => error instanceof SecurityActionOperationsError
      && error.reasonCode === "SECURITY_ACTION_OPERATIONS_SOURCE_INVALID",
  );
});

test("non-retryable suppression normalizes PostgreSQL infinity without hiding it", async () => {
  const repository = createPostgresSecurityActionOperationsRepository({
    clock: () => new Date(observedAt),
    query: async () => ({ rows: [{
      ...issueRow,
      issue_code: "ACTION_SUPPRESSED",
      severity: "info",
      action_status: "failed",
      last_failure_code: "ACTION_ALREADY_SATISFIED",
      next_attempt_at: Infinity,
      audit_event_id: null,
      audit_delivery_status: null,
      retryable: false,
    }] }),
  });
  const [issue] = await repository.listIssues();
  assert.equal(issue.nextAttemptAt, null);
  assert.equal(issue.retryable, false);
  assert.equal(issue.issueCode, "ACTION_SUPPRESSED");
});
