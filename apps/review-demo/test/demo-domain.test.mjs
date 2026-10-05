import assert from "node:assert/strict";
import { test } from "node:test";
import { getReviewState, runReviewScenario } from "../demo-domain.mjs";

const clock = () => new Date("2026-09-17T08:30:00.000Z");

test("member and administrator views preserve tenant and ownership scope", () => {
  const member = getReviewState("alpha-member");
  const admin = getReviewState("alpha-admin");
  const beta = getReviewState("beta-admin");

  assert.equal(member.records.length, 1);
  assert.equal(member.records[0].ownerSubjectId, member.persona.subjectId);
  assert.equal(admin.records.length, 2);
  assert.ok(admin.records.every((record) => record.tenantId === admin.persona.tenant.tenantId));
  assert.equal(beta.records.length, 2);
  assert.ok(beta.records.every((record) => record.tenantId === beta.persona.tenant.tenantId));
});

test("the review state derives action outcomes from the repository authorization modules", () => {
  const member = getReviewState("alpha-member");
  const admin = getReviewState("alpha-admin");

  assert.deepEqual(
    member.actionDecisions.map(({ action, outcome, scope }) => [action, outcome, scope]),
    [
      ["profile:read", "allow", "self"],
      ["record:read", "allow", "owner"],
      ["record:write", "allow", "owner"],
      ["record:export", "deny", "none"],
      ["tenant:admin", "deny", "none"],
    ],
  );
  assert.equal(admin.actionDecisions.find(({ action }) => action === "record:export").outcome, "requires-controls");
});

test("review scenarios show allow, cross-tenant denial and immediate revocation denial", () => {
  const allowed = runReviewScenario({ personaKey: "alpha-member", scenarioId: "same-tenant-record", clock });
  const crossTenant = runReviewScenario({ personaKey: "alpha-admin", scenarioId: "cross-tenant-record", clock });
  const revoked = runReviewScenario({ personaKey: "alpha-member", scenarioId: "revoked-certificate", clock });

  assert.equal(allowed.statusCode, 200);
  assert.equal(allowed.outcome, "allow");
  assert.equal(crossTenant.statusCode, 403);
  assert.equal(crossTenant.reasonCode, "ACCESS_DENIED");
  assert.equal(revoked.statusCode, 401);
  assert.equal(revoked.reasonCode, "CERTIFICATE_NOT_ACCEPTED");
});

test("sensitive export stays role-bound even when additional controls exist", () => {
  const member = runReviewScenario({ personaKey: "alpha-member", scenarioId: "sensitive-export", clock });
  const admin = runReviewScenario({ personaKey: "alpha-admin", scenarioId: "sensitive-export", clock });

  assert.equal(member.statusCode, 403);
  assert.equal(member.operationId, null);
  assert.equal(admin.statusCode, 200);
  assert.match(admin.operationId, /^op_/u);
});

test("unknown scenario IDs fail closed", () => {
  assert.throws(
    () => runReviewScenario({ personaKey: "alpha-member", scenarioId: "not-real", clock }),
    /Unknown review scenario/u,
  );
});
