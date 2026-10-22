import assert from "node:assert/strict";
import test from "node:test";

import {
  SECURITY_STATE_INVALIDATION_POLICY,
  SecurityStateInvalidationError,
  createPostgresSecurityStateInvalidationRepository,
  createRedisSecurityStateStore,
  createSecurityStateInvalidationWorker,
  securitySessionRedisKey,
  securityStateRedisKeys,
  subjectSecurityCacheRedisKey,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
  actionId: "act_018f1234-5678-7abc-8def-0123456789ad",
  certificateId: "crt_018f1234-5678-7abc-8def-0123456789ae",
  claimToken: "icl_018f1234-5678-7abc-8def-0123456789af",
});

function claim(overrides = {}) {
  return Object.freeze({
    ...ids,
    actionType: "suspend-subject",
    attemptCount: 1,
    actionSucceededAt: "2026-10-22T10:00:00.000Z",
    ...overrides,
  });
}

test("policy fixes durable delivery and a five-second enforcement target", () => {
  assert.deepEqual(SECURITY_STATE_INVALIDATION_POLICY.triggeringActions,
    ["suspend-subject", "revoke-certificate"]);
  assert.equal(SECURITY_STATE_INVALIDATION_POLICY.maximumEnforcementDelayMs, 5_000);
  assert.equal(SECURITY_STATE_INVALIDATION_POLICY.delivery,
    "durable-at-least-once-exactly-once-redis-effect");
});

test("session, cache, registry and marker keys remain tenant scoped", () => {
  const keys = securityStateRedisKeys(ids);
  assert.equal(keys.sessionIndex,
    `tenant:${ids.tenantId}:security-session-index:${ids.subjectId}`);
  assert.equal(securitySessionRedisKey({
    tenantId: ids.tenantId,
    sessionIdHashSha256: "a".repeat(64),
  }), `tenant:${ids.tenantId}:session:${"a".repeat(64)}`);
  assert.equal(subjectSecurityCacheRedisKey({
    tenantId: ids.tenantId,
    namespace: "trust-score",
    cacheId: "subject:alpha",
  }), `tenant:${ids.tenantId}:cache:trust-score:subject%3Aalpha`);
});

test("Redis registration records exact session and cache keys atomically", async () => {
  const calls = [];
  const store = createRedisSecurityStateStore({
    evaluate: async (script, options) => { calls.push({ script, options }); return 1; },
  });
  await store.registerSession({
    ...ids,
    sessionIdHashSha256: "b".repeat(64),
    value: "opaque-session",
    ttlSeconds: 300,
  });
  await store.registerCacheEntry({
    ...ids,
    namespace: "policy-state",
    cacheId: "resource-1",
    value: "cached",
    ttlSeconds: 30,
  });
  assert.equal(calls.length, 2);
  assert.match(calls[0].script, /SADD/u);
  assert.match(calls[1].options.keys[0], /:cache:policy-state:/u);
  assert.equal(calls[0].options.arguments[1], "300");
});

test("Redis invalidation uses exact registries and exposes idempotent replay", async () => {
  const calls = [];
  const replies = [[1, 2, 3, "2026-10-22T10:00:01.000Z"],
    [0, 0, 0, "2026-10-22T10:00:01.000Z"]];
  const store = createRedisSecurityStateStore({
    clock: () => new Date("2026-10-22T10:00:01.000Z"),
    evaluate: async (script, options) => {
      calls.push({ script, options });
      return replies.shift();
    },
  });
  const first = await store.invalidate(claim());
  const retry = await store.invalidate(claim());
  assert.deepEqual(first, {
    applied: true,
    sessionsInvalidated: 2,
    cacheEntriesInvalidated: 3,
    invalidatedAt: "2026-10-22T10:00:01.000Z",
  });
  assert.equal(retry.applied, false);
  assert.match(calls[0].script, /INVALID_SESSION_SCOPE/u);
  assert.equal(calls[0].options.keys.length, 3);
});

test("PostgreSQL repository claims and completes one measured invalidation", async () => {
  const calls = [];
  const repository = createPostgresSecurityStateInvalidationRepository({
    idFactory: () => "018f1234-5678-7abc-8def-0123456789af",
    clock: () => new Date("2026-10-22T10:00:01.500Z"),
    query: async (sql, values) => {
      calls.push({ sql, values });
      if (sql.includes("claim_security")) return { rows: [{
        tenant_id: ids.tenantId,
        action_id: ids.actionId,
        subject_id: ids.subjectId,
        certificate_id: ids.certificateId,
        action_type: "suspend-subject",
        claim_token: ids.claimToken,
        attempt_count: 1,
        action_succeeded_at: "2026-10-22T10:00:00.000Z",
      }] };
      return { rows: [{
        tenant_id: ids.tenantId,
        action_id: ids.actionId,
        status: "completed",
        attempt_count: 1,
        enforcement_delay_ms: 1000,
        within_target: true,
        completed_at: "2026-10-22T10:00:01.500Z",
      }] };
    },
  });
  const claimed = await repository.claimNext({ workerId: "invalidation.test-1" });
  const completed = await repository.markCompleted({
    ...claimed,
    sessionsInvalidated: 2,
    cacheEntriesInvalidated: 3,
    invalidatedAt: "2026-10-22T10:00:01.000Z",
  });
  assert.equal(completed.withinTarget, true);
  assert.match(calls[0].sql, /claim_security_state_invalidation/u);
  assert.match(calls[1].sql, /complete_security_state_invalidation/u);
  assert.deepEqual(calls[1].values.slice(3, 5), [2, 3]);
});

test("worker records session/cache counts and measured enforcement delay", async () => {
  let completion;
  const worker = createSecurityStateInvalidationWorker({
    workerId: "invalidation.test-2",
    repository: {
      claimNext: async () => claim(),
      markCompleted: async (value) => {
        completion = value;
        return {
          tenantId: ids.tenantId,
          actionId: ids.actionId,
          status: "completed",
          attemptCount: 1,
          enforcementDelayMs: 1_200,
          withinTarget: true,
          completedAt: "2026-10-22T10:00:01.300Z",
        };
      },
      markFailed: async () => assert.fail("successful invalidation must not fail"),
    },
    stateStore: {
      invalidate: async () => ({
        applied: true,
        sessionsInvalidated: 4,
        cacheEntriesInvalidated: 6,
        invalidatedAt: "2026-10-22T10:00:01.200Z",
      }),
    },
  });
  const result = await worker.runOnce();
  assert.equal(result.enforcementDelayMs, 1200);
  assert.equal(result.withinTarget, true);
  assert.equal(completion.sessionsInvalidated, 4);
  assert.equal(completion.cacheEntriesInvalidated, 6);
});

test("worker rejects a database completion that does not confirm the measured delay", async () => {
  let failure;
  const worker = createSecurityStateInvalidationWorker({
    workerId: "invalidation.test-4",
    repository: {
      claimNext: async () => claim(),
      markCompleted: async () => ({
        tenantId: ids.tenantId,
        actionId: ids.actionId,
        status: "completed",
        attemptCount: 1,
        enforcementDelayMs: 999,
        withinTarget: true,
        completedAt: "2026-10-22T10:00:01.300Z",
      }),
      markFailed: async (value) => {
        failure = value;
        return {
          tenantId: ids.tenantId,
          actionId: ids.actionId,
          status: "failed",
          attemptCount: 1,
          enforcementDelayMs: null,
          withinTarget: null,
          completedAt: null,
        };
      },
    },
    stateStore: {
      invalidate: async () => ({
        applied: true,
        sessionsInvalidated: 1,
        cacheEntriesInvalidated: 1,
        invalidatedAt: "2026-10-22T10:00:01.200Z",
      }),
    },
  });
  const result = await worker.runOnce();
  assert.equal(result.status, "failed");
  assert.equal(failure.failureCode, "SECURITY_INVALIDATION_COMPLETION_INVALID");
});

test("worker makes a Redis outage visible and retryable", async () => {
  let failure;
  const worker = createSecurityStateInvalidationWorker({
    workerId: "invalidation.test-3",
    repository: {
      claimNext: async () => claim({ attemptCount: 2 }),
      markCompleted: async () => assert.fail("failed invalidation must not complete"),
      markFailed: async (value) => {
        failure = value;
        return {
          tenantId: ids.tenantId,
          actionId: ids.actionId,
          status: "failed",
          attemptCount: 2,
          enforcementDelayMs: null,
          withinTarget: null,
          completedAt: null,
        };
      },
    },
    stateStore: { invalidate: async () => { throw new Error("Redis unavailable"); } },
  });
  const result = await worker.runOnce();
  assert.equal(result.status, "failed");
  assert.equal(failure.failureCode, "SECURITY_INVALIDATION_FAILED");
  assert.equal(failure.retryDelaySeconds, 2);
});

test("invalid actions, TTLs and malformed Redis results fail closed", async () => {
  const store = createRedisSecurityStateStore({ evaluate: async () => [1, -1, 0, "bad"] });
  await assert.rejects(
    store.invalidate(claim({ actionType: "restrict-access" })),
    (error) => error instanceof SecurityStateInvalidationError
      && error.reasonCode === "SECURITY_INVALIDATION_REQUEST_INVALID",
  );
  await assert.rejects(
    store.registerSession({
      ...ids,
      sessionIdHashSha256: "c".repeat(64),
      value: "session",
      ttlSeconds: 0,
    }),
    (error) => error.reasonCode === "SECURITY_STATE_TTL_INVALID",
  );
  await assert.rejects(
    store.invalidate(claim()),
    (error) => error.reasonCode === "SECURITY_INVALIDATION_RESULT_INVALID",
  );
});
