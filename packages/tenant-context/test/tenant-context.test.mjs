import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TENANT_CONTEXT_DENIAL,
  TenantContextError,
  assertNoTenantSwitch,
  resolveTenantContext,
  tenantSafeDenial,
} from "../src/index.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ad",
};

function validInput(overrides = {}) {
  const input = {
    authentication: {
      source: "mtls-certificate",
      authenticationId: "crt_018f1234-5678-7abc-8def-0123456789ae",
      tenantId: ids.alpha,
      subjectId: ids.alice,
    },
    authority: {
      tenant: { tenantId: ids.alpha, state: "active", version: 3 },
      subject: { subjectId: ids.alice, state: "active", version: 5 },
      membership: { tenantId: ids.alpha, subjectId: ids.alice, state: "active", version: 7 },
      roles: ["tenant-member"],
    },
  };
  return { ...input, ...overrides };
}

function expectDenial(reasonCode, operation) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof TenantContextError);
    assert.equal(error.message, "Tenant context resolution denied.");
    assert.equal(error.reasonCode, reasonCode);
    return true;
  });
}

test("derives an immutable tenant context from trusted authentication and authoritative membership", () => {
  const context = resolveTenantContext(validInput());

  assert.deepEqual(context, {
    tenantId: ids.alpha,
    subjectId: ids.alice,
    roles: ["tenant-member"],
    authentication: {
      source: "mtls-certificate",
      authenticationId: "crt_018f1234-5678-7abc-8def-0123456789ae",
    },
    versions: { tenant: 3, subject: 5, membership: 7 },
  });
  assert.ok(Object.isFrozen(context));
  assert.ok(Object.isFrozen(context.roles));
  assert.ok(Object.isFrozen(context.authentication));
  assert.ok(Object.isFrozen(context.versions));
});

test("accepts only authentication-bound mTLS or trusted-session provenance", () => {
  expectDenial("AUTHENTICATED_IDENTITY_REQUIRED", () => resolveTenantContext());
  expectDenial("AUTHENTICATION_SOURCE_UNTRUSTED", () => resolveTenantContext(validInput({
    authentication: { ...validInput().authentication, source: "request-header" },
  })));
  expectDenial("AUTHENTICATED_TENANT_REQUIRED", () => resolveTenantContext(validInput({
    authentication: { ...validInput().authentication, tenantId: undefined },
  })));

  const session = resolveTenantContext(validInput({
    authentication: {
      ...validInput().authentication,
      source: "trusted-session",
      authenticationId: "session-alpha-alice",
    },
  }));
  assert.equal(session.authentication.source, "trusted-session");
});

test("denies inactive or inconsistent authoritative identity state", () => {
  for (const [reasonCode, key] of [
    ["TENANT_INACTIVE", "tenant"],
    ["SUBJECT_INACTIVE", "subject"],
    ["MEMBERSHIP_INACTIVE", "membership"],
  ]) {
    const input = validInput();
    input.authority[key].state = "suspended";
    expectDenial(reasonCode, () => resolveTenantContext(input));
  }

  const mismatchedMembership = validInput();
  mismatchedMembership.authority.membership.tenantId = ids.beta;
  expectDenial("AUTHORITATIVE_STATE_MISMATCH", () => resolveTenantContext(mismatchedMembership));

  const platformOnly = validInput();
  platformOnly.authority.roles = ["platform-admin"];
  expectDenial("TENANT_ROLE_REQUIRED", () => resolveTenantContext(platformOnly));
});

test("client and resource tenant claims can confirm but never switch the trusted tenant", () => {
  const context = resolveTenantContext(validInput());

  expectDenial("TENANT_CONTEXT_INVALID", () => assertNoTenantSwitch({ tenantId: ids.alpha }));

  assert.equal(assertNoTenantSwitch(context, [
    { source: "header", tenantId: ids.alpha },
    { source: "path", tenantId: ids.alpha },
    { source: "query", tenantId: ids.alpha },
    { source: "body", tenantId: ids.alpha },
    { source: "resource", tenantId: ids.alpha },
  ]), context);

  for (const source of ["header", "path", "query", "body", "resource"]) {
    expectDenial("TENANT_CONTEXT_MISMATCH", () => assertNoTenantSwitch(context, [
      { source, tenantId: ids.beta },
    ]));
  }
});

test("maps every context failure to one non-enumerating external denial", () => {
  for (const reasonCode of ["TENANT_INACTIVE", "MEMBERSHIP_INACTIVE", "TENANT_CONTEXT_MISMATCH"]) {
    assert.equal(tenantSafeDenial(new TenantContextError(reasonCode)), TENANT_CONTEXT_DENIAL);
  }
  assert.deepEqual(TENANT_CONTEXT_DENIAL, { statusCode: 403, code: "ACCESS_DENIED" });
});
