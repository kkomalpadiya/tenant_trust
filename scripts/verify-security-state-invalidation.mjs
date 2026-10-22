import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  SECURITY_STATE_INVALIDATION_POLICY,
  createRedisSecurityStateStore,
  securitySessionRedisKey,
  securityStateRedisKeys,
  subjectSecurityCacheRedisKey,
} from "../services/orchestrator/src/index.mjs";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const sql = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-security-state-invalidation.sql"),
  "utf8",
);
const database = spawnSync("docker", [
  ...composeArgs, "exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", environment.POSTGRES_USER, "-d", environment.POSTGRES_DB,
], {
  cwd: repositoryRoot,
  encoding: "utf8",
  input: sql,
  maxBuffer: 4 * 1024 * 1024,
});
if (database.status !== 0) {
  const detail = (database.stderr || database.stdout || database.error?.message || "").trim();
  throw new Error(`Security-state invalidation database verification failed${detail ? `:\n${detail}` : ""}`);
}
if (database.stdout.trim()) console.log(database.stdout.trim());
if (database.stderr.trim()) console.error(database.stderr.trim());

function redis(...args) {
  const result = spawnSync("docker", [
    ...composeArgs, "exec", "-T", "redis",
    "redis-cli", "--no-auth-warning", "--raw", ...args,
  ], { cwd: repositoryRoot, encoding: "utf8" });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`Redis invalidation verification failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout.trim();
}

async function evaluate(script, { keys, arguments: values }) {
  const output = redis("EVAL", script, String(keys.length), ...keys, ...values);
  const lines = output === "" ? [] : output.split(/\r?\n/u);
  return lines.length <= 1 ? Number(lines[0]) : lines;
}

const alphaTenant = "tnt_018f1234-5678-7abc-8def-0123456789d1";
const betaTenant = "tnt_018f1234-5678-7abc-8def-0123456789d2";
const targetSubject = "sub_018f1234-5678-7abc-8def-0123456789d1";
const otherSubject = "sub_018f1234-5678-7abc-8def-0123456789d2";
const actionId = "act_018f1234-5678-7abc-8def-0123456789d1";
const suffix = randomUUID();
const alphaSessionHash = "a".repeat(64);
const otherSessionHash = "b".repeat(64);
const betaSessionHash = "c".repeat(64);
const store = createRedisSecurityStateStore({ evaluate });
const cleanup = [];

async function register(tenantId, subjectId, sessionHash, label) {
  const session = await store.registerSession({
    tenantId, subjectId, sessionIdHashSha256: sessionHash,
    value: `${label}-session`, ttlSeconds: 60,
  });
  const cache = await store.registerCacheEntry({
    tenantId, subjectId, namespace: "t9-5-verification",
    cacheId: `${label}:${suffix}`, value: `${label}-cache`, ttlSeconds: 60,
  });
  cleanup.push(session.sessionKey, session.sessionIndex, cache.cacheKey, cache.cacheIndex,
    securityStateRedisKeys({ tenantId, subjectId }).invalidationMarker);
  return { session: session.sessionKey, cache: cache.cacheKey };
}

try {
  const target = await register(alphaTenant, targetSubject, alphaSessionHash, "target");
  const neighbor = await register(alphaTenant, otherSubject, otherSessionHash, "neighbor");
  const foreign = await register(betaTenant, targetSubject, betaSessionHash, "foreign");
  assert.equal(redis("GET", target.session), "target-session");
  assert.equal(redis("GET", target.cache), "target-cache");

  const started = Date.now();
  const result = await store.invalidate({
    tenantId: alphaTenant,
    subjectId: targetSubject,
    actionId,
    actionType: "suspend-subject",
  });
  const wallDelayMs = Date.now() - started;
  assert.equal(result.applied, true);
  assert.equal(result.sessionsInvalidated, 1);
  assert.equal(result.cacheEntriesInvalidated, 1);
  assert.equal(redis("EXISTS", target.session, target.cache), "0");
  assert.equal(redis("GET", neighbor.session), "neighbor-session");
  assert.equal(redis("GET", neighbor.cache), "neighbor-cache");
  assert.equal(redis("GET", foreign.session), "foreign-session");
  assert.equal(redis("GET", foreign.cache), "foreign-cache");
  assert.ok(wallDelayMs <= SECURITY_STATE_INVALIDATION_POLICY.maximumEnforcementDelayMs,
    `live Redis invalidation took ${wallDelayMs}ms`);

  const replay = await store.invalidate({
    tenantId: alphaTenant,
    subjectId: targetSubject,
    actionId,
    actionType: "suspend-subject",
  });
  assert.equal(replay.applied, false);
  assert.equal(replay.sessionsInvalidated, 0);
  assert.equal(replay.cacheEntriesInvalidated, 0);

  assert.equal(securitySessionRedisKey({
    tenantId: alphaTenant, sessionIdHashSha256: alphaSessionHash,
  }), target.session);
  assert.equal(subjectSecurityCacheRedisKey({
    tenantId: alphaTenant,
    namespace: "t9-5-verification",
    cacheId: `target:${suffix}`,
  }), target.cache);
  console.log(`PASS target session and cache invalidated atomically in ${wallDelayMs}ms`);
  console.log("PASS same-tenant neighbor and foreign-tenant state remained intact");
  console.log("PASS exact action replay produced no second Redis effect");
} finally {
  if (cleanup.length > 0) redis("DEL", ...new Set(cleanup));
}

console.log("Security-state invalidation verification passed without retaining test data.");
