import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { PermissionViolationError, connect } from "@nats-io/transport-node";
import { subjectForEvent } from "@tenant-trust/messaging";
import {
  TenantContextError,
  resolveTenantContext,
} from "@tenant-trust/tenant-context";
import { tenantCacheKey, tenantLockKey } from "@tenant-trust/tenant-context/redis";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ad",
  betaResource: "res_018f1234-5678-7abc-8def-0123456789b2",
};

for (const key of [
  "POSTGRES_USER",
  "POSTGRES_DB",
  "NATS_HOST_PORT",
  "NATS_TENANT_ALPHA_USER",
  "NATS_TENANT_ALPHA_PASSWORD",
  "NATS_TENANT_BETA_USER",
  "NATS_TENANT_BETA_PASSWORD",
]) {
  if (!environment[key]) throw new Error(`Missing ${key}; run npm run infra:init.`);
}

function run(command, args, label, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`${label} failed${detail ? `:\n${detail}` : ""}`);
  }
  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());
}

function contextFor(tenantId, authenticationId) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId,
      tenantId,
      subjectId: ids.subject,
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: { tenantId, subjectId: ids.subject, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

function redis(...args) {
  const result = spawnSync(
    "docker",
    [...composeArgs, "exec", "-T", "redis", "redis-cli", "--no-auth-warning", ...args],
    { cwd: repositoryRoot, encoding: "utf8" },
  );
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || "").trim();
    throw new Error(`Redis tampering check failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout.trim();
}

function deadline(promise, timeoutMs, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out.`)), timeoutMs)),
  ]);
}

async function expectPermissionStatus(connection, operation, subject, action, label) {
  const statuses = connection.status()[Symbol.asyncIterator]();
  try {
    action();
    await connection.flush();
    const deadlineAt = Date.now() + 3_000;
    while (Date.now() < deadlineAt) {
      const remaining = deadlineAt - Date.now();
      const status = await deadline(statuses.next(), remaining, label);
      if (status.done) break;
      if (status.value.type !== "error") continue;
      const error = status.value.error;
      assert.ok(error instanceof PermissionViolationError, `${label} returned an unexpected error.`);
      assert.equal(error.operation, operation);
      assert.equal(error.subject, subject);
      return;
    }
    assert.fail(`${label} did not emit a permission violation.`);
  } finally {
    await statuses.return?.();
  }
}

run(
  process.execPath,
  ["--test", "packages/tenant-context/test/cross-tenant-tampering.test.mjs"],
  "API-facing tenant tampering tests",
);

const databaseSql = readFileSync(
  resolve(repositoryRoot, "database/tests/verify-cross-tenant-tampering.sql"),
  "utf8",
);
run(
  "docker",
  [
    ...composeArgs,
    "exec",
    "-T",
    "postgres",
    "psql",
    "-X",
    "-v",
    "ON_ERROR_STOP=1",
    "-U",
    environment.POSTGRES_USER,
    "-d",
    environment.POSTGRES_DB,
  ],
  "PostgreSQL cross-tenant tampering tests",
  { input: databaseSql },
);

const alphaContext = contextFor(ids.alpha, "tampering-alpha");
const betaContext = contextFor(ids.beta, "tampering-beta");
const suffix = randomUUID();
const betaCacheKey = tenantCacheKey(betaContext, "tampering", ids.betaResource, suffix);
const guessedCacheKey = tenantCacheKey(alphaContext, "tampering", ids.betaResource, suffix);
const ambiguousCacheKey = tenantCacheKey(alphaContext, "tampering", "resource:version", suffix);
const separatedCacheKey = tenantCacheKey(alphaContext, "tampering", "resource", "version", suffix);
const guessedLockKey = tenantLockKey(alphaContext, "tampering", ids.betaResource, suffix);

try {
  assert.notEqual(guessedCacheKey, betaCacheKey);
  assert.notEqual(ambiguousCacheKey, separatedCacheKey);
  assert.notEqual(guessedCacheKey, guessedLockKey);
  assert.throws(
    () => tenantCacheKey({ tenantId: ids.beta }, "tampering", ids.betaResource),
    (error) => error instanceof TenantContextError && error.reasonCode === "TENANT_CONTEXT_INVALID",
  );
  assert.equal(redis("SET", betaCacheKey, "beta-secret", "EX", "60"), "OK");
  assert.equal(redis("GET", guessedCacheKey), "");
  assert.equal(redis("SET", guessedCacheKey, "alpha-guess", "EX", "60"), "OK");
  assert.equal(redis("GET", betaCacheKey), "beta-secret");
  console.log("PASS Redis guessed IDs, forged contexts and ambiguous key segments remain tenant-scoped");
} finally {
  redis("DEL", betaCacheKey, guessedCacheKey, ambiguousCacheKey, separatedCacheKey, guessedLockKey);
}

const server = `nats://127.0.0.1:${environment.NATS_HOST_PORT}`;
const alphaConnection = await connect({
  servers: server,
  user: environment.NATS_TENANT_ALPHA_USER,
  pass: environment.NATS_TENANT_ALPHA_PASSWORD,
  name: "tenant-alpha-tampering-verifier",
  timeout: 5_000,
});
const betaConnection = await connect({
  servers: server,
  user: environment.NATS_TENANT_BETA_USER,
  pass: environment.NATS_TENANT_BETA_PASSWORD,
  name: "tenant-beta-tampering-verifier",
  timeout: 5_000,
});
const alphaSubject = `tenant.${ids.alpha}.events.tampering.probe.v1`;
const betaSubject = `tenant.${ids.beta}.events.tampering.probe.v1`;

try {
  assert.throws(
    () => subjectForEvent(alphaContext, { tenantId: ids.beta, eventType: "tampering.probe.v1" }),
    (error) => error instanceof TenantContextError && error.reasonCode === "TENANT_CONTEXT_MISMATCH",
  );

  await expectPermissionStatus(
    alphaConnection,
    "subscription",
    betaSubject,
    () => alphaConnection.subscribe(betaSubject),
    "Alpha cross-tenant subscription",
  );
  await expectPermissionStatus(
    betaConnection,
    "subscription",
    alphaSubject,
    () => betaConnection.subscribe(alphaSubject),
    "Beta cross-tenant subscription",
  );
  await expectPermissionStatus(
    alphaConnection,
    "publish",
    betaSubject,
    () => alphaConnection.publish(betaSubject, new TextEncoder().encode("tampering-probe")),
    "Alpha cross-tenant publish",
  );
  await expectPermissionStatus(
    betaConnection,
    "publish",
    alphaSubject,
    () => betaConnection.publish(alphaSubject, new TextEncoder().encode("tampering-probe")),
    "Beta cross-tenant publish",
  );
  console.log("PASS NATS helpers and broker credentials deny cross-tenant subjects in both directions");
} finally {
  await Promise.allSettled([alphaConnection.drain(), betaConnection.drain()]);
}

console.log("Cross-tenant access and identifier tampering verification passed.");
