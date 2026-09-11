import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { PermissionViolationError, connect } from "@nats-io/transport-node";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import { tenantCacheKey, tenantLockKey } from "@tenant-trust/tenant-context/redis";
import { composeArgs, environment, repositoryRoot } from "./lib/foundation-context.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ad",
};

for (const key of [
  "NATS_HOST_PORT",
  "NATS_TENANT_ALPHA_USER",
  "NATS_TENANT_ALPHA_PASSWORD",
  "NATS_TENANT_BETA_USER",
  "NATS_TENANT_BETA_PASSWORD",
]) {
  if (!environment[key]) throw new Error(`Missing ${key}; run npm run infra:init.`);
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
  const result = spawnSync("docker", [...composeArgs, "exec", "-T", "redis", "redis-cli", "--no-auth-warning", ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout).trim();
    throw new Error(`Redis isolation command failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout.trim();
}

function deadline(promise, timeoutMs, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out.`)), timeoutMs)),
  ]);
}

async function nextMessage(subscription, label) {
  const result = await deadline(subscription[Symbol.asyncIterator]().next(), 3_000, label);
  assert.equal(result.done, false, `${label} closed before receiving a message.`);
  return result.value;
}

async function expectSubscriptionDenied(connection, subject, label) {
  const subscription = connection.subscribe(subject);
  await connection.flush();
  const error = await deadline(subscription.closed, 3_000, label);
  assert.ok(error instanceof PermissionViolationError, `${label} did not fail with a permission violation.`);
  assert.equal(error.operation, "subscription");
  assert.equal(error.subject, subject);
}

const alphaContext = contextFor(ids.alpha, "runtime-isolation-alpha");
const betaContext = contextFor(ids.beta, "runtime-isolation-beta");
const suffix = randomUUID();
const alphaCacheKey = tenantCacheKey(alphaContext, "verification", suffix);
const betaCacheKey = tenantCacheKey(betaContext, "verification", suffix);
const alphaLockKey = tenantLockKey(alphaContext, "verification", suffix);
const betaLockKey = tenantLockKey(betaContext, "verification", suffix);

try {
  assert.equal(redis("SET", alphaCacheKey, "alpha", "EX", "60"), "OK");
  assert.equal(redis("SET", betaCacheKey, "beta", "EX", "60"), "OK");
  assert.equal(redis("GET", alphaCacheKey), "alpha");
  assert.equal(redis("GET", betaCacheKey), "beta");
  assert.equal(redis("SET", alphaLockKey, "alpha", "NX", "EX", "60"), "OK");
  assert.equal(redis("SET", betaLockKey, "beta", "NX", "EX", "60"), "OK");
  assert.equal(redis("SET", alphaLockKey, "duplicate", "NX", "EX", "60"), "");
  console.log("PASS Redis cache and lock keys separate identical logical names by trusted tenant context");
} finally {
  redis("DEL", alphaCacheKey, betaCacheKey, alphaLockKey, betaLockKey);
}

const server = `nats://127.0.0.1:${environment.NATS_HOST_PORT}`;
const alphaConnection = await connect({
  servers: server,
  user: environment.NATS_TENANT_ALPHA_USER,
  pass: environment.NATS_TENANT_ALPHA_PASSWORD,
  name: "tenant-alpha-isolation-verifier",
  timeout: 5_000,
});
const betaConnection = await connect({
  servers: server,
  user: environment.NATS_TENANT_BETA_USER,
  pass: environment.NATS_TENANT_BETA_PASSWORD,
  name: "tenant-beta-isolation-verifier",
  timeout: 5_000,
});

const alphaSubject = `tenant.${ids.alpha}.events.verification.ping.v1`;
const betaSubject = `tenant.${ids.beta}.events.verification.ping.v1`;

try {
  const alphaOwn = alphaConnection.subscribe(alphaSubject, { max: 1 });
  const betaOwn = betaConnection.subscribe(betaSubject, { max: 1 });
  await Promise.all([alphaConnection.flush(), betaConnection.flush()]);

  alphaConnection.publish(alphaSubject, new TextEncoder().encode("alpha"));
  betaConnection.publish(betaSubject, new TextEncoder().encode("beta"));
  await Promise.all([alphaConnection.flush(), betaConnection.flush()]);

  assert.equal((await nextMessage(alphaOwn, "Alpha own-tenant delivery")).string(), "alpha");
  assert.equal((await nextMessage(betaOwn, "Beta own-tenant delivery")).string(), "beta");
  console.log("PASS NATS tenant credentials publish and consume only their own tenant subjects");

  await expectSubscriptionDenied(alphaConnection, betaSubject, "Alpha cross-tenant subscription");
  await expectSubscriptionDenied(betaConnection, alphaSubject, "Beta cross-tenant subscription");
  console.log("PASS NATS rejects cross-tenant consumer subscriptions at the broker");
} finally {
  await Promise.allSettled([alphaConnection.drain(), betaConnection.drain()]);
}

console.log("Runtime tenant isolation verification passed.");
