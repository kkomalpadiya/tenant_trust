import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveTenantContext, TenantContextError } from "../src/index.mjs";
import { tenantCacheKey, tenantLockKey } from "../src/redis.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ad",
};

function contextFor(tenantId, authenticationId) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId,
      tenantId,
      subjectId: ids.alice,
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId: ids.alice, state: "active", version: 1 },
      membership: { tenantId, subjectId: ids.alice, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

const alpha = contextFor(ids.alpha, "session-alpha");
const beta = contextFor(ids.beta, "session-beta");

test("cache keys derive tenant scope only from a resolved context", () => {
  const alphaKey = tenantCacheKey(alpha, "trust-score", "subject:shared");
  const betaKey = tenantCacheKey(beta, "trust-score", "subject:shared");

  assert.equal(alphaKey, `tenant:${ids.alpha}:cache:trust-score:subject%3Ashared`);
  assert.equal(betaKey, `tenant:${ids.beta}:cache:trust-score:subject%3Ashared`);
  assert.notEqual(alphaKey, betaKey);
});

test("cache and lock namespaces cannot collide", () => {
  assert.notEqual(
    tenantCacheKey(alpha, "decision", "resource-1"),
    tenantLockKey(alpha, "decision", "resource-1"),
  );
});

test("key construction rejects forged context and ambiguous input", () => {
  assert.throws(
    () => tenantCacheKey({ tenantId: ids.alpha }, "trust-score", "subject-1"),
    (error) => error instanceof TenantContextError && error.reasonCode === "TENANT_CONTEXT_INVALID",
  );
  assert.throws(() => tenantCacheKey(alpha, "Trust Score", "subject-1"), /namespace/u);
  assert.throws(() => tenantLockKey(alpha, "decision"), /key segment/u);
  assert.throws(() => tenantLockKey(alpha, "decision", ""), /key segment/u);
});
