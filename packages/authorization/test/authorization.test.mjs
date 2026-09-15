import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveTenantContext, TenantContextError } from "@tenant-trust/tenant-context";
import {
  ACTIONS,
  AUTHORIZATION_DENIAL,
  AuthorizationError,
  RESOURCE_SENSITIVITY,
  RESOURCE_TYPES,
  ROLE_ACTION_MATRIX,
  assertBaselineActionAllowed,
  authorizationSafeDenial,
  resolveRoleAction,
} from "../src/index.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ad",
};

function contextFor(roles) {
  return resolveTenantContext({
    authentication: {
      source: "mtls-certificate",
      authenticationId: "crt_018f1234-5678-7abc-8def-0123456789ae",
      tenantId: ids.tenant,
      subjectId: ids.subject,
    },
    authority: {
      tenant: { tenantId: ids.tenant, state: "active", version: 1 },
      subject: { subjectId: ids.subject, state: "active", version: 1 },
      membership: { tenantId: ids.tenant, subjectId: ids.subject, state: "active", version: 1 },
      roles,
    },
  });
}

const member = contextFor(["tenant-member"]);
const admin = contextFor(["tenant-admin"]);

test("defines one immutable rule for every tenant role and action", () => {
  assert.equal(ROLE_ACTION_MATRIX.length, 10);
  assert.equal(new Set(ROLE_ACTION_MATRIX.map(({ role, action }) => `${role}:${action}`)).size, 10);
  assert.ok(Object.isFrozen(ROLE_ACTION_MATRIX));

  for (const entry of ROLE_ACTION_MATRIX) {
    assert.ok(Object.isFrozen(entry));
    assert.ok(Object.isFrozen(entry.requiredControls));
    assert.equal(entry.resourceType, RESOURCE_TYPES[entry.action]);
    assert.equal(entry.sensitivity, RESOURCE_SENSITIVITY[entry.action]);
  }
});

test("member permissions are restricted to self and owned resources", () => {
  assert.deepEqual(
    ACTIONS.map((action) => {
      const decision = resolveRoleAction(member, action);
      return [action, decision.disposition, decision.scope];
    }),
    [
      ["profile:read", "allow", "self"],
      ["record:read", "allow", "owner"],
      ["record:write", "allow", "owner"],
      ["record:export", "deny", "none"],
      ["tenant:admin", "deny", "none"],
    ],
  );
});

test("administrator permissions widen record scope but never implicitly allow sensitive actions", () => {
  assert.deepEqual(
    ACTIONS.map((action) => {
      const decision = resolveRoleAction(admin, action);
      return [action, decision.disposition, decision.scope, decision.sensitivity];
    }),
    [
      ["profile:read", "allow", "self", "confidential"],
      ["record:read", "allow", "tenant", "confidential"],
      ["record:write", "allow", "tenant", "confidential"],
      ["record:export", "requires-controls", "tenant", "sensitive"],
      ["tenant:admin", "requires-controls", "tenant", "critical"],
    ],
  );

  for (const action of ["record:export", "tenant:admin"]) {
    const decision = resolveRoleAction(admin, action);
    assert.equal(decision.requiredControls.includes("operation-policy"), true);
    assert.equal(decision.requiredControls.includes("bound-step-up"), true);
    assert.throws(
      () => assertBaselineActionAllowed(admin, action),
      (error) => error instanceof AuthorizationError
        && error.reasonCode === "ADDITIONAL_CONTROLS_REQUIRED",
    );
  }
});

test("an authoritative dual-role context resolves deterministically to tenant-admin scope", () => {
  const both = contextFor(["tenant-member", "tenant-admin"]);
  assert.equal(resolveRoleAction(both, "record:read").scope, "tenant");
  assert.equal(resolveRoleAction(both, "record:export").disposition, "requires-controls");
});

test("unknown actions are immutable default denials without reflecting attacker input", () => {
  const attackerAction = "tenant:admin:*?tenant=tnt_other";
  const decision = resolveRoleAction(admin, attackerAction);

  assert.deepEqual(decision, {
    role: "none",
    action: "unknown",
    resourceType: "unknown",
    sensitivity: "restricted",
    disposition: "deny",
    scope: "none",
    requiredControls: [],
    reason: "default-deny",
  });
  assert.ok(Object.isFrozen(decision));
  assert.equal(JSON.stringify(decision).includes(attackerAction), false);
});

test("authorization accepts only a tenant context resolved from trusted identity and authority", () => {
  assert.throws(
    () => resolveRoleAction({ ...admin }, "record:read"),
    (error) => error instanceof TenantContextError && error.reasonCode === "TENANT_CONTEXT_INVALID",
  );
});

test("baseline enforcement allows only explicit allow entries and returns one safe denial", () => {
  assert.equal(assertBaselineActionAllowed(member, "profile:read").scope, "self");
  assert.equal(assertBaselineActionAllowed(admin, "record:write").scope, "tenant");

  for (const action of ["record:export", "tenant:admin", "not-defined"]) {
    try {
      assertBaselineActionAllowed(member, action);
      assert.fail("denied action was accepted");
    } catch (error) {
      if (error?.code === "ERR_ASSERTION") throw error;
      assert.deepEqual(authorizationSafeDenial(error), AUTHORIZATION_DENIAL);
    }
  }
});
