import assert from "node:assert/strict";
import { test } from "node:test";

import {
  INITIAL_SECURITY_ACTION_STATE,
  SecurityActionStateMachineError,
  evaluateSecurityActionRecovery,
  evaluateSecurityActionTriggers,
  transitionSecurityActionState,
} from "../src/index.mjs";

const TARGET = Object.freeze({
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789a0",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789b0",
});
const SOURCE_A = "src_018f1234-5678-7abc-8def-0123456789c0";
const SOURCE_B = "src_018f1234-5678-7abc-8def-0123456789c1";
const EVALUATED_AT = "2026-10-22T12:05:00.000Z";

function severeEvidence(index, overrides = {}) {
  return {
    evidenceId: `evd_018f1234-5678-7abc-8def-${String(123456789000 + index).padStart(12, "0")}`,
    sourceId: SOURCE_A,
    tenantId: TARGET.tenantId,
    subjectId: TARGET.subjectId,
    kind: index % 2 === 0 ? "identity-compromised" : "device-compromised",
    componentId: index % 2 === 0 ? "identity" : "device",
    observedAt: "2026-10-22T12:04:00.000Z",
    ...overrides,
  };
}

function checkpoint(overrides = {}) {
  return {
    score: 75,
    band: "high",
    transition: "recovered",
    consecutiveQualifyingEvaluations: 2,
    sourceIds: [SOURCE_A, SOURCE_B],
    ...overrides,
  };
}

function recoveryInput(currentState, overrides = {}) {
  return {
    target: TARGET,
    currentState,
    checkpoint: checkpoint(),
    activeSevereEvidence: [],
    evaluatedAt: EVALUATED_AT,
    severeCauseResolved: true,
    ...overrides,
  };
}

test("oscillating trust cannot silently restore or progressively escalate state", () => {
  const restricted = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "restrict-access",
  });
  const replayedRestriction = transitionSecurityActionState({
    currentState: restricted.state,
    actionType: "restrict-access",
  });
  assert.equal(replayedRestriction.changed, false);
  assert.deepEqual(replayedRestriction.state, restricted.state);

  const incomplete = evaluateSecurityActionRecovery(recoveryInput(restricted.state, {
    checkpoint: checkpoint({ consecutiveQualifyingEvaluations: 1 }),
  }));
  assert.equal(incomplete.eligible, false);
  assert.equal(incomplete.reasonCode, "TRUST_RECOVERY_INCOMPLETE");
  assert.deepEqual(restricted.state, {
    access: "restricted",
    renewal: "allowed",
    targetCertificate: "active",
    replacement: "not-required",
  });

  const eligible = evaluateSecurityActionRecovery(recoveryInput(restricted.state));
  assert.equal(eligible.nextActionType, "restore-access");
  assert.equal(eligible.authorizationRequired, "recovery-authorization");
  assert.deepEqual(restricted.state, replayedRestriction.state);

  const restored = transitionSecurityActionState({
    currentState: restricted.state,
    actionType: eligible.nextActionType,
  });
  const restrictedAgain = transitionSecurityActionState({
    currentState: restored.state,
    actionType: "restrict-access",
  });
  assert.equal(restrictedAgain.state.access, "restricted");
  assert.equal(restrictedAgain.state.targetCertificate, "active");
  assert.equal(restrictedAgain.state.replacement, "not-required");
});

test("one compromised source cannot manufacture revocation corroboration", () => {
  const result = evaluateSecurityActionTriggers({
    target: TARGET,
    policyDecision: { outcome: "ALLOW" },
    trustTransition: {
      score: 20,
      band: "low",
      transition: "critical-override",
      criticalOverride: { kind: "identity-compromised", componentId: "identity" },
    },
    severeEvidence: Array.from({ length: 6 }, (_, index) => severeEvidence(index)),
    evaluatedAt: EVALUATED_AT,
  });

  assert.equal(result.corroboration.sourceIds.length, 1);
  assert.equal(result.corroboration.enoughSources, false);
  assert.equal(result.corroboration.enoughKinds, true);
  assert.equal(result.revocationAuthorized, false);
  assert.deepEqual(result.actionTypes, ["block-renewal"]);
});

test("active severe evidence blocks recovery even after a qualifying trust rebound", () => {
  const suspended = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "suspend-subject",
  }).state;
  const result = evaluateSecurityActionRecovery(recoveryInput(suspended, {
    activeSevereEvidence: [severeEvidence(10)],
  }));

  assert.equal(result.eligible, false);
  assert.equal(result.nextActionType, null);
  assert.equal(result.reasonCode, "ACTIVE_SEVERE_EVIDENCE");
  assert.equal(suspended.access, "suspended");
  assert.equal(suspended.renewal, "blocked");
});

test("revocation remains irreversible across replay and terminal feedback", () => {
  const first = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "revoke-certificate",
  });
  const replay = transitionSecurityActionState({
    currentState: first.state,
    actionType: "revoke-certificate",
  });
  assert.equal(first.changed, true);
  assert.equal(replay.changed, false);
  assert.equal(replay.state.targetCertificate, "revoked");

  assert.throws(
    () => transitionSecurityActionState({
      currentState: first.state,
      actionType: "restore-access",
    }),
    (error) => error instanceof SecurityActionStateMachineError
      && error.reasonCode === "REPLACEMENT_REQUIRED_BEFORE_RECOVERY",
  );
  assert.throws(
    () => evaluateSecurityActionTriggers({
      target: TARGET,
      policyDecision: { outcome: "ALLOW" },
      trustTransition: {
        score: 0,
        band: "low",
        transition: "critical-override",
        criticalOverride: { kind: "certificate-revoked", componentId: "certificate" },
      },
      severeEvidence: [severeEvidence(20, {
        kind: "certificate-revoked",
        componentId: "certificate",
      })],
      evaluatedAt: EVALUATED_AT,
    }),
    (error) => error instanceof SecurityActionStateMachineError
      && error.reasonCode === "SEVERE_EVIDENCE_NOT_ACTIONABLE",
  );
});
