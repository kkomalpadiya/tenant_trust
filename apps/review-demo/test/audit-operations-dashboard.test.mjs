import assert from "node:assert/strict";
import { test } from "node:test";
import { createAuditOperationsDashboard } from "../audit-operations-dashboard.mjs";
import { reviewIds } from "../demo-domain.mjs";

test("member audit operations remain self scoped and expose all delivery outcomes", () => {
  const { auditOperations } = createAuditOperationsDashboard().getState("alpha-member");

  assert.equal(auditOperations.scope.mode, "self");
  assert.equal(auditOperations.scope.subjectId, reviewIds.alice);
  assert.ok(auditOperations.ledgerDeliveries.every(({ tenantId, subjectId }) => (
    tenantId === reviewIds.alphaTenant && subjectId === reviewIds.alice
  )));
  assert.deepEqual(
    new Set(auditOperations.ledgerDeliveries.map(({ deliveryStatus }) => deliveryStatus)),
    new Set(["committed", "pending", "failed"]),
  );
});

test("administrators receive only their tenant audit and action records", () => {
  const alpha = createAuditOperationsDashboard().getState("alpha-admin").auditOperations;
  const beta = createAuditOperationsDashboard().getState("beta-admin").auditOperations;

  assert.equal(alpha.scope.mode, "tenant");
  assert.ok(alpha.ledgerDeliveries.every(({ tenantId }) => tenantId === reviewIds.alphaTenant));
  assert.ok(alpha.securityActions.some(({ subjectId }) => subjectId === reviewIds.alice));
  assert.ok(alpha.securityActions.some(({ subjectId }) => subjectId === reviewIds.alphaAdmin));
  assert.ok(beta.ledgerDeliveries.every(({ tenantId }) => tenantId === reviewIds.betaTenant));
  assert.ok(beta.securityActions.every(({ tenantId }) => tenantId === reviewIds.betaTenant));
  assert.ok(!JSON.stringify(beta).includes(reviewIds.alphaTenant));
});

test("causal verification makes verified, waiting and failed checks explicit", () => {
  const { auditOperations } = createAuditOperationsDashboard().getState("alpha-admin");

  assert.deepEqual(auditOperations.summary.causal, { verified: 1, waiting: 1, failed: 1 });
  assert.ok(auditOperations.causalChecks.some(({ reasonCode }) => reasonCode === "CAUSATION_LINK_MISSING"));
  assert.ok(auditOperations.causalChecks.some(({ verifiedLinks }) => verifiedLinks.includes("certificate action")));
});

test("quarantine and recovery failures remain operationally actionable", () => {
  const { auditOperations } = createAuditOperationsDashboard().getState("alpha-admin");
  const failure = auditOperations.securityActions.find(({ status }) => status === "failed");

  assert.equal(auditOperations.summary.health, "critical");
  assert.equal(failure.authority, "policy-quarantine");
  assert.equal(failure.retryable, true);
  assert.equal(failure.auditDeliveryStatus, "failed");
  assert.match(failure.nextAttemptAt, /Z$/u);
  assert.equal(auditOperations.policies.auditDeliveryRequiredForHealthy, true);
  assert.equal(auditOperations.policies.stuckPendingSeconds, 300);
});

test("the dashboard projection contains no raw evidence, payload or credential fields", () => {
  const state = createAuditOperationsDashboard().getState("alpha-admin");
  const serialized = JSON.stringify(state);

  assert.equal(state.auditOperations.privacy.evidenceContentFields, 0);
  assert.equal(state.auditOperations.privacy.secretFields, 0);
  assert.doesNotMatch(serialized, /privateKey|password|token|canonicalPreimage|rawEvidence|eventPayload/u);
  assert.equal(Object.isFrozen(state.auditOperations), true);
  assert.equal(Object.isFrozen(state.auditOperations.ledgerDeliveries), true);
});
