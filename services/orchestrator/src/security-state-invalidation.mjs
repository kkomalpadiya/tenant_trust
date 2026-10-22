import { randomUUID } from "node:crypto";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CLAIM_TOKEN = /^icl_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const CACHE_NAMESPACE = /^[a-z][a-z0-9-]{0,63}$/u;
const INVALIDATING_ACTIONS = new Set(["suspend-subject", "revoke-certificate"]);
const STATUSES = new Set(["pending", "executing", "completed", "failed"]);
const SQL = Object.freeze({
  claim: "SELECT * FROM orchestration.claim_security_state_invalidation($1,$2,$3)",
  complete: "SELECT * FROM orchestration.complete_security_state_invalidation($1,$2,$3,$4,$5,$6,$7)",
  fail: "SELECT * FROM orchestration.fail_security_state_invalidation($1,$2,$3,$4,$5,$6)",
});

const REGISTER_ENTRY_LUA = `
local ttl = tonumber(ARGV[2])
if not ttl or ttl < 1 then return redis.error_reply('INVALID_TTL') end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ttl)
redis.call('SADD', KEYS[2], KEYS[1])
local index_ttl = redis.call('TTL', KEYS[2])
if index_ttl < ttl then redis.call('EXPIRE', KEYS[2], ttl) end
return 1
`;

const INVALIDATE_SUBJECT_LUA = `
local prior = redis.call('GET', KEYS[3])
if prior then
  local separator = string.find(prior, '|', 1, true)
  if separator and string.sub(prior, 1, separator - 1) == ARGV[1] then
    return {0, 0, 0, string.sub(prior, separator + 1)}
  end
end
local sessions = redis.call('SMEMBERS', KEYS[1])
local caches = redis.call('SMEMBERS', KEYS[2])
for _, key in ipairs(sessions) do
  if string.sub(key, 1, string.len(ARGV[4])) ~= ARGV[4] then
    return redis.error_reply('INVALID_SESSION_SCOPE')
  end
end
for _, key in ipairs(caches) do
  if string.sub(key, 1, string.len(ARGV[5])) ~= ARGV[5] then
    return redis.error_reply('INVALID_CACHE_SCOPE')
  end
end
local session_count = 0
for _, key in ipairs(sessions) do session_count = session_count + redis.call('DEL', key) end
local cache_count = 0
for _, key in ipairs(caches) do cache_count = cache_count + redis.call('DEL', key) end
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('SET', KEYS[3], ARGV[1] .. '|' .. ARGV[2], 'EX', tonumber(ARGV[3]))
return {1, session_count, cache_count, ARGV[2]}
`;

export const SECURITY_STATE_INVALIDATION_POLICY = Object.freeze({
  triggeringActions: Object.freeze([...INVALIDATING_ACTIONS]),
  delivery: "durable-at-least-once-exactly-once-redis-effect",
  maximumEnforcementDelayMs: 5_000,
  workerPollIntervalMs: 1_000,
  claimLeaseSeconds: 30,
  initialRetryDelaySeconds: 1,
  maximumRetryDelaySeconds: 60,
  invalidationMarkerTtlSeconds: 604_800,
  maximumEntryTtlSeconds: 86_400,
});

export class SecurityStateInvalidationError extends Error {
  constructor(reasonCode, options) {
    super("Security-state invalidation failed.", options);
    this.name = "SecurityStateInvalidationError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new SecurityStateInvalidationError(
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

function iso(value, reasonCode = "SECURITY_INVALIDATION_SOURCE_INVALID") {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) fail(reasonCode);
  return date.toISOString();
}

function integer(value, reasonCode) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) fail(reasonCode);
  return parsed;
}

function retryDelay(attemptCount) {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) {
    fail("SECURITY_INVALIDATION_SOURCE_INVALID");
  }
  return Math.min(
    SECURITY_STATE_INVALIDATION_POLICY.maximumRetryDelaySeconds,
    SECURITY_STATE_INVALIDATION_POLICY.initialRetryDelaySeconds
      * (2 ** Math.min(attemptCount - 1, 30)),
  );
}

function failureCode(error) {
  return /^[A-Z][A-Z0-9_]{2,63}$/u.test(error?.reasonCode ?? "")
    ? error.reasonCode
    : "SECURITY_INVALIDATION_FAILED";
}

function keyPart(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 255) {
    throw new TypeError(`${label} must be a non-empty string of at most 255 characters.`);
  }
  return encodeURIComponent(value);
}

function assertScope({ tenantId, subjectId }) {
  if (!TENANT_ID.test(tenantId ?? "") || !SUBJECT_ID.test(subjectId ?? "")) {
    fail("SECURITY_INVALIDATION_SCOPE_INVALID");
  }
}

export function securityStateRedisKeys({ tenantId, subjectId }) {
  assertScope({ tenantId, subjectId });
  const subject = keyPart(subjectId, "subject ID");
  return Object.freeze({
    sessionIndex: `tenant:${tenantId}:security-session-index:${subject}`,
    cacheIndex: `tenant:${tenantId}:security-cache-index:${subject}`,
    invalidationMarker: `tenant:${tenantId}:security-invalidation:${subject}`,
    sessionPrefix: `tenant:${tenantId}:session:`,
    cachePrefix: `tenant:${tenantId}:cache:`,
  });
}

export function securitySessionRedisKey({ tenantId, sessionIdHashSha256 }) {
  if (!TENANT_ID.test(tenantId ?? "") || !SHA256.test(sessionIdHashSha256 ?? "")) {
    fail("SECURITY_SESSION_KEY_INVALID");
  }
  return `tenant:${tenantId}:session:${sessionIdHashSha256}`;
}

export function subjectSecurityCacheRedisKey({ tenantId, namespace, cacheId }) {
  if (!TENANT_ID.test(tenantId ?? "") || !CACHE_NAMESPACE.test(namespace ?? "")) {
    fail("SECURITY_CACHE_KEY_INVALID");
  }
  return `tenant:${tenantId}:cache:${namespace}:${keyPart(cacheId, "cache ID")}`;
}

export function createRedisSecurityStateStore({ evaluate, clock = () => new Date() } = {}) {
  if (typeof evaluate !== "function" || typeof clock !== "function") {
    throw new TypeError("A Redis script evaluator and clock are required.");
  }
  function ttl(value) {
    if (!Number.isSafeInteger(value) || value < 1
      || value > SECURITY_STATE_INVALIDATION_POLICY.maximumEntryTtlSeconds) {
      fail("SECURITY_STATE_TTL_INVALID");
    }
    return String(value);
  }
  return Object.freeze({
    async registerSession({ tenantId, subjectId, sessionIdHashSha256, value, ttlSeconds }) {
      const keys = securityStateRedisKeys({ tenantId, subjectId });
      const sessionKey = securitySessionRedisKey({ tenantId, sessionIdHashSha256 });
      if (typeof value !== "string" || value.length < 1 || value.length > 4096) {
        fail("SECURITY_SESSION_VALUE_INVALID");
      }
      await evaluate(REGISTER_ENTRY_LUA, {
        keys: [sessionKey, keys.sessionIndex],
        arguments: [value, ttl(ttlSeconds)],
      });
      return Object.freeze({ sessionKey, sessionIndex: keys.sessionIndex });
    },

    async registerCacheEntry({ tenantId, subjectId, namespace, cacheId, value, ttlSeconds }) {
      const keys = securityStateRedisKeys({ tenantId, subjectId });
      const cacheKey = subjectSecurityCacheRedisKey({ tenantId, namespace, cacheId });
      if (typeof value !== "string" || value.length > 65_536) {
        fail("SECURITY_CACHE_VALUE_INVALID");
      }
      await evaluate(REGISTER_ENTRY_LUA, {
        keys: [cacheKey, keys.cacheIndex],
        arguments: [value, ttl(ttlSeconds)],
      });
      return Object.freeze({ cacheKey, cacheIndex: keys.cacheIndex });
    },

    async invalidate({ tenantId, subjectId, actionId, actionType }) {
      assertScope({ tenantId, subjectId });
      if (!ACTION_ID.test(actionId ?? "") || !INVALIDATING_ACTIONS.has(actionType)) {
        fail("SECURITY_INVALIDATION_REQUEST_INVALID");
      }
      const invalidatedAt = iso(clock(), "SECURITY_INVALIDATION_TIME_INVALID");
      const keys = securityStateRedisKeys({ tenantId, subjectId });
      let raw;
      try {
        raw = await evaluate(INVALIDATE_SUBJECT_LUA, {
          keys: [keys.sessionIndex, keys.cacheIndex, keys.invalidationMarker],
          arguments: [
            actionId,
            invalidatedAt,
            String(SECURITY_STATE_INVALIDATION_POLICY.invalidationMarkerTtlSeconds),
            keys.sessionPrefix,
            keys.cachePrefix,
          ],
        });
      } catch (error) {
        fail("SECURITY_INVALIDATION_REDIS_FAILED", error);
      }
      if (!Array.isArray(raw) || raw.length !== 4 || ![0, 1].includes(Number(raw[0]))) {
        fail("SECURITY_INVALIDATION_RESULT_INVALID");
      }
      return Object.freeze({
        applied: Number(raw[0]) === 1,
        sessionsInvalidated: integer(raw[1], "SECURITY_INVALIDATION_RESULT_INVALID"),
        cacheEntriesInvalidated: integer(raw[2], "SECURITY_INVALIDATION_RESULT_INVALID"),
        invalidatedAt: iso(raw[3], "SECURITY_INVALIDATION_RESULT_INVALID"),
      });
    },
  });
}

function mapClaim(row) {
  if (!row) return null;
  const claim = {
    tenantId: row.tenant_id,
    actionId: row.action_id,
    subjectId: row.subject_id,
    certificateId: row.certificate_id,
    actionType: row.action_type,
    claimToken: row.claim_token,
    attemptCount: Number(row.attempt_count),
    actionSucceededAt: iso(row.action_succeeded_at),
  };
  if (!TENANT_ID.test(claim.tenantId ?? "")
    || !ACTION_ID.test(claim.actionId ?? "")
    || !SUBJECT_ID.test(claim.subjectId ?? "")
    || typeof claim.certificateId !== "string"
    || !INVALIDATING_ACTIONS.has(claim.actionType)
    || !CLAIM_TOKEN.test(claim.claimToken ?? "")
    || !Number.isSafeInteger(claim.attemptCount)
    || claim.attemptCount < 1) {
    fail("SECURITY_INVALIDATION_SOURCE_INVALID");
  }
  return Object.freeze(claim);
}

function mapStatus(row) {
  const status = {
    tenantId: row?.tenant_id,
    actionId: row?.action_id,
    status: row?.status,
    attemptCount: Number(row?.attempt_count),
    enforcementDelayMs: row?.enforcement_delay_ms === null
      || row?.enforcement_delay_ms === undefined
      ? null : Number(row.enforcement_delay_ms),
    withinTarget: row?.within_target ?? null,
    completedAt: row?.completed_at ? iso(row.completed_at) : null,
  };
  if (!TENANT_ID.test(status.tenantId ?? "")
    || !ACTION_ID.test(status.actionId ?? "")
    || !STATUSES.has(status.status)
    || !Number.isSafeInteger(status.attemptCount)
    || status.attemptCount < 0
    || (status.enforcementDelayMs !== null
      && (!Number.isSafeInteger(status.enforcementDelayMs) || status.enforcementDelayMs < 0))
    || (status.withinTarget !== null && typeof status.withinTarget !== "boolean")) {
    fail("SECURITY_INVALIDATION_STATUS_INVALID");
  }
  return Object.freeze(status);
}

export function createPostgresSecurityStateInvalidationRepository({
  query,
  idFactory = randomUUID,
  clock = () => new Date(),
} = {}) {
  if (typeof query !== "function" || typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("A PostgreSQL query function, ID factory and clock are required.");
  }
  const now = () => iso(clock(), "SECURITY_INVALIDATION_TIME_INVALID");
  return Object.freeze({
    async claimNext({ workerId }, options = {}) {
      if (!WORKER_ID.test(workerId ?? "")) fail("SECURITY_INVALIDATION_CLAIM_INVALID");
      const token = `icl_${idFactory()}`;
      if (!CLAIM_TOKEN.test(token)) fail("SECURITY_INVALIDATION_CLAIM_INVALID");
      return mapClaim(maybeOne(await query(SQL.claim, [workerId, token, now()], options),
        "SECURITY_INVALIDATION_SOURCE_INVALID"));
    },

    async markCompleted(value, options = {}) {
      if (!TENANT_ID.test(value?.tenantId ?? "")
        || !ACTION_ID.test(value?.actionId ?? "")
        || !CLAIM_TOKEN.test(value?.claimToken ?? "")
        || !Number.isSafeInteger(value?.sessionsInvalidated)
        || value.sessionsInvalidated < 0
        || !Number.isSafeInteger(value?.cacheEntriesInvalidated)
        || value.cacheEntriesInvalidated < 0) {
        fail("SECURITY_INVALIDATION_COMPLETION_INVALID");
      }
      return mapStatus(one(await query(SQL.complete, [
        value.tenantId,
        value.actionId,
        value.claimToken,
        value.sessionsInvalidated,
        value.cacheEntriesInvalidated,
        iso(value.invalidatedAt, "SECURITY_INVALIDATION_COMPLETION_INVALID"),
        now(),
      ], options), "SECURITY_INVALIDATION_COMPLETION_INVALID"));
    },

    async markFailed(value, options = {}) {
      if (!TENANT_ID.test(value?.tenantId ?? "")
        || !ACTION_ID.test(value?.actionId ?? "")
        || !CLAIM_TOKEN.test(value?.claimToken ?? "")
        || !/^[A-Z][A-Z0-9_]{2,63}$/u.test(value?.failureCode ?? "")
        || !Number.isSafeInteger(value?.retryDelaySeconds)
        || value.retryDelaySeconds < 1
        || value.retryDelaySeconds > SECURITY_STATE_INVALIDATION_POLICY.maximumRetryDelaySeconds) {
        fail("SECURITY_INVALIDATION_FAILURE_INVALID");
      }
      return mapStatus(one(await query(SQL.fail, [
        value.tenantId,
        value.actionId,
        value.claimToken,
        value.failureCode,
        now(),
        value.retryDelaySeconds,
      ], options), "SECURITY_INVALIDATION_FAILURE_INVALID"));
    },
  });
}

export function createSecurityStateInvalidationWorker({ workerId, repository, stateStore } = {}) {
  if (!WORKER_ID.test(workerId ?? "")
    || !repository
    || ["claimNext", "markCompleted", "markFailed"].some(
      (name) => typeof repository[name] !== "function",
    )
    || !stateStore
    || typeof stateStore.invalidate !== "function") {
    throw new TypeError("A valid worker, repository and security-state store are required.");
  }
  return Object.freeze({
    async runOnce(options) {
      const claim = await repository.claimNext({ workerId }, options);
      if (!claim) return Object.freeze({ status: "idle" });
      try {
        const result = await stateStore.invalidate(claim);
        const delay = new Date(result.invalidatedAt).getTime()
          - new Date(claim.actionSucceededAt).getTime();
        if (!Number.isSafeInteger(delay) || delay < 0) {
          fail("SECURITY_INVALIDATION_RESULT_INVALID");
        }
        const stored = await repository.markCompleted({
          ...claim,
          ...result,
        }, options);
        const withinTarget = delay
          <= SECURITY_STATE_INVALIDATION_POLICY.maximumEnforcementDelayMs;
        if (stored.status !== "completed"
          || stored.enforcementDelayMs !== delay
          || stored.withinTarget !== withinTarget) {
          fail("SECURITY_INVALIDATION_COMPLETION_INVALID");
        }
        return Object.freeze({
          status: stored.status,
          tenantId: claim.tenantId,
          actionId: claim.actionId,
          actionType: claim.actionType,
          applied: result.applied,
          sessionsInvalidated: result.sessionsInvalidated,
          cacheEntriesInvalidated: result.cacheEntriesInvalidated,
          enforcementDelayMs: delay,
          withinTarget,
        });
      } catch (error) {
        const stored = await repository.markFailed({
          ...claim,
          failureCode: failureCode(error),
          retryDelaySeconds: retryDelay(claim.attemptCount),
        }, options);
        return Object.freeze({
          status: stored.status,
          tenantId: claim.tenantId,
          actionId: claim.actionId,
          actionType: claim.actionType,
          attemptCount: claim.attemptCount,
          failureCode: failureCode(error),
        });
      }
    },
  });
}
