import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustDashboard } from "../trust-dashboard.mjs";
import { reviewIds } from "../demo-domain.mjs";

const fixedTime = "2026-10-27T10:00:00.000Z";

test("members see only their own trust explanation and decisions", () => {
  const state = createTrustDashboard({ clock: () => new Date(fixedTime) }).getState("alpha-member");

  assert.equal(state.trustSubjects.length, 1);
  assert.equal(state.trustSubjects[0].subjectId, reviewIds.alice);
  assert.equal(state.trustSubjects[0].tenantId, reviewIds.alphaTenant);
  assert.equal(state.trustSummary.currentSubjectId, reviewIds.alice);
});

test("administrators see trust history only for subjects in their tenant", () => {
  const service = createTrustDashboard({ clock: () => new Date(fixedTime) });
  const alpha = service.getState("alpha-admin");
  const beta = service.getState("beta-admin");

  assert.deepEqual(alpha.trustSubjects.map(({ subjectId }) => subjectId).sort(), [reviewIds.alice, reviewIds.alphaAdmin].sort());
  assert.ok(alpha.trustSubjects.every(({ tenantId }) => tenantId === reviewIds.alphaTenant));
  assert.deepEqual(beta.trustSubjects.map(({ subjectId }) => subjectId).sort(), [reviewIds.bob, reviewIds.betaAdmin].sort());
  assert.ok(beta.trustSubjects.every(({ tenantId }) => tenantId === reviewIds.betaTenant));
});

test("current explanations expose all weighted components and immutable versions", () => {
  const subject = createTrustDashboard({ clock: () => new Date(fixedTime) })
    .getState("alpha-member").trustSubjects[0];
  const contributionTotal = subject.components.reduce((total, component) => total + component.weightedContribution, 0);
  const weightTotal = subject.components.reduce((total, component) => total + component.weight, 0);

  assert.deepEqual(subject.components.map(({ id }) => id), ["identity", "device", "behaviour", "certificate", "compliance"]);
  assert.equal(Number(contributionTotal.toFixed(2)), subject.current.lastKnownScore);
  assert.equal(weightTotal, 1);
  assert.equal(subject.current.modelVersion, "1.0.0");
  assert.equal(subject.current.configurationVersion, 1);
  assert.match(subject.policy.policyVersionId, /^pol_/u);
  assert.equal(subject.policy.bundleVersion, 3);
});

test("freshness is usable at the boundary and withholds the policy score when stale", () => {
  let now = new Date(fixedTime);
  const service = createTrustDashboard({ clock: () => new Date(now) });
  const initial = service.getState("alpha-member").trustSubjects[0];
  const observedAt = Date.parse(initial.current.observedAt);

  now = new Date(observedAt + initial.freshness.staleAfterSeconds * 1000);
  const boundary = service.getState("alpha-member").trustSubjects[0];
  assert.equal(boundary.freshness.state, "fresh");
  assert.equal(boundary.current.policyScore, boundary.current.lastKnownScore);

  now = new Date(now.getTime() + 1);
  const stale = service.getState("alpha-member").trustSubjects[0];
  assert.equal(stale.freshness.state, "stale");
  assert.equal(stale.freshness.reasonCode, "TRUST_STATE_STALE");
  assert.equal(stale.current.policyScore, null);
});

test("decision and transition histories carry reasons and tenant policy provenance", () => {
  const state = createTrustDashboard({ clock: () => new Date(fixedTime) }).getState("beta-admin");
  const bob = state.trustSubjects.find(({ subjectId }) => subjectId === reviewIds.bob);
  const noah = state.trustSubjects.find(({ subjectId }) => subjectId === reviewIds.betaAdmin);

  assert.equal(bob.decisions[0].outcome, "QUARANTINE");
  assert.deepEqual(bob.decisions[0].reasonCodes, ["TRUST_SCORE_QUARANTINE"]);
  assert.equal(noah.decisions[0].outcome, "STEP_UP");
  assert.deepEqual(noah.decisions[0].reasonCodes, ["STEP_UP_REQUIRED"]);
  assert.ok(bob.decisions.every(({ policyVersionId }) => policyVersionId === state.trustSummary.policyVersionId));
  assert.ok(bob.transitions.every((transition, index, items) => index === 0
    || Date.parse(items[index - 1].observedAt) >= Date.parse(transition.observedAt)));
});

test("denied and certificate-rejected access attempts immediately reduce trust", () => {
  const service = createTrustDashboard({ clock: () => new Date(fixedTime) });
  const before = service.getState("alpha-member").trustSubjects[0];
  const denied = {
    scenarioId: "forged-identity-header",
    outcome: "deny",
    reasonCode: "ACCESS_DENIED",
    event: { action: "record:read" },
  };
  const firstImpact = service.recordScenario({ personaKey: "alpha-member", result: denied });
  const afterDenied = service.getState("alpha-member").trustSubjects[0];

  assert.equal(firstImpact.previousScore, before.current.lastKnownScore);
  assert(firstImpact.newScore < firstImpact.previousScore);
  assert.equal(afterDenied.transitions[0].reasonCode, "SUSPICIOUS_ACCESS_EVIDENCE");

  const certificateImpact = service.recordScenario({
    personaKey: "alpha-member",
    result: {
      scenarioId: "same-tenant-record",
      outcome: "deny",
      reasonCode: "CERTIFICATE_NOT_ACCEPTED",
      event: { action: "record:read" },
    },
  });
  const afterCertificate = service.getState("alpha-member").trustSubjects[0];

  assert(certificateImpact.newScore < firstImpact.newScore);
  assert.equal(afterCertificate.components.find(({ id }) => id === "certificate").value, 0);
  assert.equal(afterCertificate.transitions[0].reasonCode, "CERTIFICATE_REJECTION_EVIDENCE");
});
