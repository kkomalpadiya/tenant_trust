import assert from "node:assert/strict";
import test from "node:test";

import {
  SecurityActionOrchestrationError,
  createPostgresSecurityActionRepository,
  createSecurityActionExecutor,
  createSecurityActionWorker,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  actionId: "act_018f1234-5678-7abc-8def-0123456789e1",
  decisionId: "dec_018f1234-5678-7abc-8def-0123456789e2",
  correlationId: "cor_018f1234-5678-7abc-8def-0123456789e3",
  targetSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
  targetCertificateId: "crt_018f1234-5678-7abc-8def-0123456789e4",
  claimToken: "clm_018f1234-5678-7abc-8def-0123456789e5",
});

function claim(overrides = {}) {
  return Object.freeze({
    ...ids,
    actionType: "restrict-access",
    authorityClass: "policy-quarantine",
    reasonCode: "TRUST_SCORE_QUARANTINE",
    triggerContextHashSha256: "a".repeat(64),
    attemptCount: 1,
    expectedStateVersion: 1,
    currentState: Object.freeze({
      access: "normal",
      renewal: "allowed",
      targetCertificate: "active",
      replacement: "not-required",
    }),
    ...overrides,
  });
}

function status(overrides = {}) {
  return {
    tenant_id: ids.tenantId,
    action_id: ids.actionId,
    status: "pending",
    attempt_count: 0,
    last_failure_code: null,
    next_attempt_at: "2026-10-22T10:00:00.000Z",
    succeeded_at: null,
    ...overrides,
  };
}

test("PostgreSQL repository preserves the supplied stable action ID", async () => {
  const calls = [];
  const repository = createPostgresSecurityActionRepository({
    clock: () => new Date("2026-10-22T10:00:00.000Z"),
    query: async (sql, values) => {
      calls.push({ sql, values });
      return { rows: [status()] };
    },
  });
  const queued = await repository.enqueueSeverityAction({
    ...ids,
    actionType: "block-renewal",
    reasonCode: "CRITICAL_EVIDENCE_PENDING",
    triggerContextHashSha256: "b".repeat(64),
  });

  assert.equal(queued.actionId, ids.actionId);
  assert.match(calls[0].sql, /enqueue_severity_security_action/u);
  assert.equal(calls[0].values[1], ids.actionId);
  assert.equal(calls[0].values[8], "2026-10-22T10:00:00.000Z");
});

test("worker executes and persists a tenant-scoped restriction", async () => {
  const stored = [];
  const repository = {
    claimNext: async () => claim(),
    markSucceeded: async (value) => {
      stored.push(value);
      return {
        tenantId: ids.tenantId, actionId: ids.actionId, status: "succeeded",
        attemptCount: 1, lastFailureCode: null, nextAttemptAt: null,
        succeededAt: "2026-10-22T10:00:01.000Z",
      };
    },
    markFailed: async () => assert.fail("success must not be stored as failure"),
  };
  const worker = createSecurityActionWorker({
    workerId: "orchestrator.test-1",
    repository,
    executor: createSecurityActionExecutor(),
  });

  const result = await worker.runOnce();
  assert.equal(result.status, "succeeded");
  assert.equal(result.actionId, ids.actionId);
  assert.equal(result.changed, true);
  assert.deepEqual(result.state, {
    access: "restricted", renewal: "allowed",
    targetCertificate: "active", replacement: "not-required",
  });
  assert.equal(stored[0].actionId, ids.actionId);
  assert.equal(stored[0].claimToken, ids.claimToken);
});

test("worker persists retryable failure against the same action ID", async () => {
  const failures = [];
  const repository = {
    claimNext: async () => claim({ attemptCount: 2 }),
    markSucceeded: async () => assert.fail("failure must not be stored as success"),
    markFailed: async (value) => {
      failures.push(value);
      return {
        tenantId: ids.tenantId, actionId: ids.actionId, status: "failed",
        attemptCount: 2, lastFailureCode: value.failureCode,
        nextAttemptAt: "2026-10-22T10:00:10.000Z", succeededAt: null,
      };
    },
  };
  const worker = createSecurityActionWorker({
    workerId: "orchestrator.test-2",
    repository,
    executor: { execute: async () => { throw new Error("temporary outage"); } },
  });

  const result = await worker.runOnce();
  assert.equal(result.status, "failed");
  assert.equal(result.actionId, ids.actionId);
  assert.equal(result.failureCode, "ACTION_EXECUTION_FAILED");
  assert.equal(failures[0].retryDelaySeconds, 10);
  assert.equal(failures[0].actionId, ids.actionId);
});

test("an exact replayed state transition succeeds without changing state again", async () => {
  let saved;
  const alreadyRestricted = claim({
    expectedStateVersion: 8,
    currentState: Object.freeze({
      access: "restricted", renewal: "allowed",
      targetCertificate: "active", replacement: "not-required",
    }),
  });
  const worker = createSecurityActionWorker({
    workerId: "orchestrator.test-3",
    repository: {
      claimNext: async () => alreadyRestricted,
      markSucceeded: async (value) => {
        saved = value;
        return {
          tenantId: ids.tenantId, actionId: ids.actionId, status: "succeeded",
          attemptCount: 1, lastFailureCode: null, nextAttemptAt: null,
          succeededAt: "2026-10-22T10:00:01.000Z",
        };
      },
      markFailed: async () => assert.fail("idempotent success must not fail"),
    },
    executor: createSecurityActionExecutor(),
  });

  const result = await worker.runOnce();
  assert.equal(result.changed, false);
  assert.deepEqual(saved.resultState, alreadyRestricted.currentState);
});

test("certificate revocation requires an exact external confirmation", async () => {
  const action = claim({ actionType: "revoke-certificate" });
  const executor = createSecurityActionExecutor({
    revokeCertificate: async () => ({
      certificateId: ids.targetCertificateId,
      state: "revoked",
      eventId: "evt_018f1234-5678-7abc-8def-0123456789e6",
    }),
  });
  const result = await executor.execute(action);
  assert.equal(result.actionId, ids.actionId);
  assert.equal(result.externalReference, "evt_018f1234-5678-7abc-8def-0123456789e6");

  await assert.rejects(
    createSecurityActionExecutor({
      revokeCertificate: async () => ({ certificateId: "wrong", state: "revoked", eventId: "evt_bad" }),
    }).execute(action),
    (error) => error instanceof SecurityActionOrchestrationError
      && error.reasonCode === "REVOCATION_EXECUTION_UNCONFIRMED",
  );
});

test("recovery execution requires a live governed authorization", async () => {
  const authorization = {
    recoveryAuthorizationId: "rca_018f1234-5678-7abc-8def-0123456789e6",
    recoveryAuthorizedBySubjectId: ids.targetSubjectId,
    recoveryAuthorizedUntil: "2026-10-22T10:05:00.000Z",
    causeResolutionReference: null,
  };
  let stored;
  const worker = createSecurityActionWorker({
    workerId: "orchestrator.test-4",
    repository: {
      claimNext: async () => claim({
        actionType: "restore-access",
        authorityClass: "recovery-authorization",
        ...authorization,
        currentState: Object.freeze({
          access: "restricted", renewal: "blocked",
          targetCertificate: "active", replacement: "not-required",
        }),
      }),
      markSucceeded: async (value) => {
        stored = value;
        return {
          tenantId: ids.tenantId, actionId: ids.actionId, status: "succeeded",
          attemptCount: 1, lastFailureCode: null, nextAttemptAt: null,
          succeededAt: "2026-10-22T10:00:01.000Z",
        };
      },
      markFailed: async () => assert.fail("authorized recovery must not fail"),
    },
    executor: createSecurityActionExecutor({
      clock: () => new Date("2026-10-22T10:00:00.000Z"),
    }),
  });

  const result = await worker.runOnce();
  assert.equal(result.status, "succeeded");
  assert.deepEqual(stored.resultState, {
    access: "normal", renewal: "allowed",
    targetCertificate: "active", replacement: "not-required",
  });

  await assert.rejects(
    createSecurityActionExecutor({
      clock: () => new Date("2026-10-22T10:00:00.000Z"),
    }).execute(claim({
      actionType: "restore-access",
      authorityClass: "recovery-authorization",
    })),
    (error) => error instanceof SecurityActionOrchestrationError
      && error.reasonCode === "RECOVERY_AUTHORIZATION_INVALID",
  );
});

test("replacement execution confirms a fresh distinct certificate", async () => {
  const action = claim({
    actionType: "issue-replacement-certificate",
    authorityClass: "recovery-authorization",
    recoveryAuthorizationId: "rca_018f1234-5678-7abc-8def-0123456789e6",
    recoveryAuthorizedBySubjectId: ids.targetSubjectId,
    recoveryAuthorizedUntil: "2026-10-22T10:05:00.000Z",
    causeResolutionReference: "case:resolved:123",
  });
  const replacementCertificateId = "crt_018f1234-5678-7abc-8def-0123456789e7";
  const executor = createSecurityActionExecutor({
    clock: () => new Date("2026-10-22T10:00:00.000Z"),
    issueReplacementCertificate: async () => ({
      targetCertificateId: ids.targetCertificateId,
      replacementCertificateId,
      state: "active",
    }),
  });
  assert.equal((await executor.execute(action)).externalReference, replacementCertificateId);

  await assert.rejects(
    createSecurityActionExecutor({
      clock: () => new Date("2026-10-22T10:00:00.000Z"),
      issueReplacementCertificate: async () => ({
        targetCertificateId: ids.targetCertificateId,
        replacementCertificateId: ids.targetCertificateId,
        state: "active",
      }),
    }).execute(action),
    (error) => error instanceof SecurityActionOrchestrationError
      && error.reasonCode === "REPLACEMENT_ISSUANCE_UNCONFIRMED",
  );
});

test("repository fails closed on malformed claimed work", async () => {
  const repository = createPostgresSecurityActionRepository({
    idFactory: () => "018f1234-5678-7abc-8def-0123456789e5",
    clock: () => new Date("2026-10-22T10:00:00.000Z"),
    query: async () => ({ rows: [{
      ...status(),
      decision_id: ids.decisionId,
      correlation_id: ids.correlationId,
      target_subject_id: ids.targetSubjectId,
      target_certificate_id: ids.targetCertificateId,
      action_type: "drop-database",
      authority_class: "policy-quarantine",
      reason_code: "TRUST_SCORE_QUARANTINE",
      trigger_context_hash_sha256: "a".repeat(64),
      claim_token: ids.claimToken,
      attempt_count: 1,
      expected_state_version: 1,
      access_state: "normal",
      renewal_state: "allowed",
      target_certificate_state: "active",
      replacement_state: "not-required",
    }] }),
  });
  await assert.rejects(
    repository.claimNext({ workerId: "orchestrator.test-5" }),
    (error) => error instanceof SecurityActionOrchestrationError
      && error.reasonCode === "SECURITY_ACTION_SOURCE_INVALID",
  );
});
