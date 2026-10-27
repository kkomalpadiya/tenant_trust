import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { ACTIONS, RESOURCE_TYPES, ROLE_ACTION_MATRIX } from "@tenant-trust/authorization";
import { TenantContextError } from "@tenant-trust/tenant-context";
import {
  COMPARISON_WORKLOAD_ID,
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_IDS,
  EVALUATION_RESOURCES,
  EVALUATION_SUBJECTS,
  EVALUATION_TENANTS,
  EVALUATION_WORKLOAD,
  JWT_RBAC_BASELINE_POLICY,
  JwtRbacBaselineError,
  createJwtRbacEvaluationBaseline,
  createJwtRbacEvaluationTokenIssuer,
  jwtRbacSafeDenial,
} from "../src/index.mjs";

const fixedTime = new Date("2026-10-28T08:00:00.000Z");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
let sequence = 1;
const idFactory = () => `018f1234-5678-7abc-8def-${String(sequence++).padStart(12, "0")}`;
const common = {
  keyId: "evaluation-key-v1",
  issuer: "tenant-trust-evaluation",
  audience: "tenant-trust-api",
  clock: () => fixedTime,
};
const issuer = createJwtRbacEvaluationTokenIssuer({ privateKey, ...common, idFactory });
const baseline = createJwtRbacEvaluationBaseline({ publicKey, ...common });

function subject(subjectId) {
  return EVALUATION_SUBJECTS.find((entry) => entry.subjectId === subjectId);
}

function authorityFor(entry, overrides = {}) {
  return {
    tenant: { tenantId: entry.tenantId, state: "active", version: 4 },
    subject: { subjectId: entry.subjectId, state: "active", version: 3 },
    membership: { tenantId: entry.tenantId, subjectId: entry.subjectId, state: "active", version: 6 },
    ...overrides,
  };
}

function issueFor(entry, ttlSeconds = 300) {
  return issuer.issue({
    tenantId: entry.tenantId,
    subjectId: entry.subjectId,
    roles: [entry.role],
    ttlSeconds,
  });
}

test("all three comparison modes share one exact tenant, resource, action and workload scope", () => {
  assert.equal(EVALUATION_TENANTS.length, 2);
  assert.equal(EVALUATION_SUBJECTS.length, 4);
  assert.equal(EVALUATION_COMPARISON_SCOPE.workloadId, COMPARISON_WORKLOAD_ID);
  assert.ok(EVALUATION_COMPARISON_SCOPE.modes.every(({ workloadId }) => workloadId === COMPARISON_WORKLOAD_ID));
  assert.deepEqual(EVALUATION_COMPARISON_SCOPE.actions, ACTIONS);
  assert.deepEqual(new Set(EVALUATION_WORKLOAD.map(({ action }) => action)), new Set(ACTIONS));
  assert.ok(EVALUATION_WORKLOAD.every(({ resourceKey, action }) => (
    EVALUATION_RESOURCES[resourceKey].resourceType === RESOURCE_TYPES[action]
  )));
  assert.equal(ROLE_ACTION_MATRIX.length, 10);
});

test("issuer creates a bounded EdDSA JWT and verifier returns only signed identity claims", () => {
  const entry = subject(EVALUATION_IDS.alice);
  const issued = issueFor(entry, 120);
  const claims = baseline.verifyToken(issued.token);

  assert.equal(issued.token.split(".").length, 3);
  assert.deepEqual(claims, issued.claims);
  assert.equal(claims.exp - claims.iat, 120);
  assert.deepEqual(claims.roles, ["tenant-member"]);
  assert.doesNotMatch(JSON.stringify(issued), /private|secret|password/u);
  assert.equal(Object.isFrozen(claims), true);
});

test("the complete shared workload produces the declared JWT plus RBAC outcomes", () => {
  const issuedBySubject = new Map(EVALUATION_SUBJECTS.map((entry) => [entry.subjectId, issueFor(entry)]));

  for (const workloadCase of EVALUATION_WORKLOAD) {
    const actor = subject(workloadCase.actorSubjectId);
    const decision = baseline.authorize({
      token: issuedBySubject.get(actor.subjectId).token,
      authority: authorityFor(actor),
      action: workloadCase.action,
      resource: EVALUATION_RESOURCES[workloadCase.resourceKey],
    });
    assert.equal(decision.outcome, workloadCase.expectedJwtOutcome, workloadCase.workloadCaseId);
    assert.equal(decision.reasonCode, workloadCase.expectedJwtReason, workloadCase.workloadCaseId);
  }
});

test("JWT baseline permits administrator sensitive actions from signed role and tenant scope alone", () => {
  const actor = subject(EVALUATION_IDS.alphaAdmin);
  const token = issueFor(actor).token;

  for (const [action, resourceKey] of [["record:export", "alphaExport"], ["tenant:admin", "alphaMembership"]]) {
    const decision = baseline.authorize({ token, authority: authorityFor(actor), action, resource: EVALUATION_RESOURCES[resourceKey] });
    assert.equal(decision.outcome, "allow");
    assert.equal(decision.eligibility.disposition, "requires-controls");
    assert.equal(decision.rbacOnly, true);
    assert.equal(decision.adaptiveTrustUsed, false);
    assert.equal("trustScore" in decision, false);
    assert.equal("certificatePolicy" in decision, false);
  }
});

test("member ownership and cross-tenant resource scope deny without disclosing the target", () => {
  const alice = subject(EVALUATION_IDS.alice);
  const admin = subject(EVALUATION_IDS.alphaAdmin);
  const aliceToken = issueFor(alice).token;
  const adminToken = issueFor(admin).token;
  const peer = baseline.authorize({
    token: aliceToken,
    authority: authorityFor(alice),
    action: "record:read",
    resource: EVALUATION_RESOURCES.alphaAdminRecord,
  });
  const foreign = baseline.authorize({
    token: adminToken,
    authority: authorityFor(admin),
    action: "record:read",
    resource: EVALUATION_RESOURCES.betaMemberRecord,
  });

  assert.equal(peer.reasonCode, "RESOURCE_SCOPE_DENIED");
  assert.equal(foreign.reasonCode, "RESOURCE_SCOPE_DENIED");
  assert.equal(JSON.stringify(foreign).includes(EVALUATION_IDS.betaTenant), false);
});

test("tampered, wrong-key and expired tokens fail with one safe external denial", () => {
  const entry = subject(EVALUATION_IDS.alice);
  const issued = issueFor(entry, 1);
  const parts = issued.token.split(".");
  const tampered = `${parts[0]}.${parts[1].slice(0, -1)}A.${parts[2]}`;
  const otherKeys = generateKeyPairSync("ed25519");
  const wrongKeyBaseline = createJwtRbacEvaluationBaseline({ publicKey: otherKeys.publicKey, ...common });
  const expiredBaseline = createJwtRbacEvaluationBaseline({
    publicKey,
    ...common,
    clock: () => new Date(fixedTime.getTime() + 2_000),
  });

  for (const [service, token] of [[baseline, tampered], [wrongKeyBaseline, issued.token], [expiredBaseline, issued.token]]) {
    try {
      service.verifyToken(token);
      assert.fail("invalid token was accepted");
    } catch (error) {
      if (error?.code === "ERR_ASSERTION") throw error;
      assert.deepEqual(jwtRbacSafeDenial(error), { statusCode: 401, code: "AUTHENTICATION_FAILED" });
    }
  }
});

test("token claims cannot bypass current tenant, subject or membership state", () => {
  const entry = subject(EVALUATION_IDS.alice);
  const token = issueFor(entry).token;
  const inactive = authorityFor(entry, {
    membership: { tenantId: entry.tenantId, subjectId: entry.subjectId, state: "suspended", version: 7 },
  });

  assert.throws(
    () => baseline.authorize({ token, authority: inactive, action: "profile:read", resource: EVALUATION_RESOURCES.aliceProfile }),
    (error) => error instanceof TenantContextError && error.reasonCode === "MEMBERSHIP_INACTIVE",
  );
  assert.throws(
    () => baseline.authorize({
      token,
      authority: authorityFor(entry, { tenant: { tenantId: EVALUATION_IDS.betaTenant, state: "active", version: 4 } }),
      action: "profile:read",
      resource: EVALUATION_RESOURCES.aliceProfile,
    }),
    (error) => error instanceof TenantContextError && error.reasonCode === "AUTHORITATIVE_STATE_MISMATCH",
  );
});

test("JWT policy is immutable, bounded and explicitly evaluation-only", () => {
  assert.deepEqual(JWT_RBAC_BASELINE_POLICY, {
    modeId: "jwt-rbac-baseline-v1",
    authenticationPolicy: "signed-jwt-eddsa-v1",
    rolePolicy: "role-action-matrix-v1",
    algorithm: "EdDSA",
    maximumTokenTtlSeconds: 300,
    adaptiveTrustUsed: false,
    certificateRequired: false,
    sensitiveOperationsUseRoleOnly: true,
  });
  assert.equal(Object.isFrozen(JWT_RBAC_BASELINE_POLICY), true);
  assert.throws(
    () => issuer.issue({ tenantId: EVALUATION_IDS.alphaTenant, subjectId: EVALUATION_IDS.alice, roles: ["tenant-member"], ttlSeconds: 301 }),
    (error) => error instanceof JwtRbacBaselineError && error.reasonCode === "JWT_TTL_INVALID",
  );
});
