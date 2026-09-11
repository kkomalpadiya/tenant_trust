import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TENANT_CONTEXT_DENIAL,
  assertNoTenantSwitch,
  resolveTenantContext,
  tenantSafeDenial,
} from "../src/index.mjs";

const ids = {
  alpha: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  beta: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ad",
};

function alphaInput() {
  return {
    authentication: {
      source: "trusted-session",
      authenticationId: "session-alpha-tampering-test",
      tenantId: ids.alpha,
      subjectId: ids.alice,
    },
    authority: {
      tenant: { tenantId: ids.alpha, state: "active", version: 1 },
      subject: { subjectId: ids.alice, state: "active", version: 1 },
      membership: { tenantId: ids.alpha, subjectId: ids.alice, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  };
}

function externalDenial(operation) {
  try {
    operation();
    assert.fail("tampering attempt was accepted");
  } catch (error) {
    if (error?.code === "ERR_ASSERTION") throw error;
    return tenantSafeDenial(error);
  }
}

function assertOpaqueDenial(response) {
  assert.deepEqual(response, TENANT_CONTEXT_DENIAL);
  const serialized = JSON.stringify(response);
  assert.equal(serialized.includes(ids.alpha), false);
  assert.equal(serialized.includes(ids.beta), false);
  assert.equal(serialized.includes("resource"), false);
  assert.equal(serialized.includes("reason"), false);
}

test("API-facing tenant claims cannot switch the authenticated tenant", () => {
  const context = resolveTenantContext(alphaInput());

  for (const source of ["header", "path", "query", "body", "resource"]) {
    assertOpaqueDenial(externalDenial(() => assertNoTenantSwitch(context, [
      { source, tenantId: ids.beta },
    ])));
  }
});

test("malformed, forged and inconsistent API-facing identity state has one external denial", () => {
  const context = resolveTenantContext(alphaInput());
  const mismatchedAuthority = alphaInput();
  mismatchedAuthority.authority.membership.tenantId = ids.beta;

  for (const operation of [
    () => assertNoTenantSwitch(context, [{ source: "path", tenantId: "not-a-tenant" }]),
    () => assertNoTenantSwitch({ tenantId: ids.alpha }, [{ source: "path", tenantId: ids.alpha }]),
    () => resolveTenantContext(mismatchedAuthority),
    () => resolveTenantContext({
      ...alphaInput(),
      authentication: { ...alphaInput().authentication, tenantId: ids.beta },
    }),
  ]) {
    assertOpaqueDenial(externalDenial(operation));
  }
});
