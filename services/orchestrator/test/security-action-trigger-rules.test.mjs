import assert from "node:assert/strict";
import { test } from "node:test";
import {
  INITIAL_SECURITY_ACTION_STATE,
  SECURITY_ACTION_RECOVERY_POLICY,
  SECURITY_ACTION_TRIGGER_POLICY,
  SecurityActionStateMachineError,
  evaluateSecurityActionRecovery,
  evaluateSecurityActionTriggers,
  transitionSecurityActionState,
} from "../src/index.mjs";
import { DEFAULT_TRUST_TRANSITION_CONFIGURATION } from "@tenant-trust/trust";

const TARGET = Object.freeze({
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789a0",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789b0",
});
const OTHER_TARGET = Object.freeze({
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789a1",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789b1",
});
const SOURCE_A = "src_018f1234-5678-7abc-8def-0123456789c0";
const SOURCE_B = "src_018f1234-5678-7abc-8def-0123456789c1";
const EVALUATED_AT = "2026-10-22T12:05:00.000Z";

function evidence({
  evidenceId = "evd_018f1234-5678-7abc-8def-0123456789d0",
  sourceId = SOURCE_A,
  target = TARGET,
  kind = "identity-compromised",
  componentId = "identity",
  observedAt = "2026-10-22T12:04:00.000Z",
} = {}) {
  return {
    evidenceId,
    sourceId,
    tenantId: target.tenantId,
    subjectId: target.subjectId,
    kind,
    componentId,
    observedAt,
  };
}

function triggerInput(overrides = {}) {
  return {
    target: TARGET,
    policyDecision: { outcome: "ALLOW" },
    trustTransition: {
      score: 80,
      band: "high",
      transition: "held",
      criticalOverride: null,
    },
    severeEvidence: [],
    evaluatedAt: EVALUATED_AT,
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

test("inherits the existing trust recovery thresholds and corroboration counts", () => {
  assert.equal(
    SECURITY_ACTION_RECOVERY_POLICY.restricted.minimumScore,
    DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.low.recoveryThreshold,
  );
  assert.equal(
    SECURITY_ACTION_RECOVERY_POLICY.suspendedOrRenewalBlocked.minimumScore,
    DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.recoveryThreshold,
  );
  assert.equal(
    SECURITY_ACTION_RECOVERY_POLICY.requiredDistinctSources,
    DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.distinctSourceCount,
  );
  assert.equal(
    SECURITY_ACTION_RECOVERY_POLICY.requiredConsecutiveQualifyingEvaluations,
    DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations,
  );
});

test("maps a validated low-trust quarantine only to reversible containment", () => {
  const result = evaluateSecurityActionTriggers(triggerInput({
    policyDecision: { outcome: "QUARANTINE", quarantineActionType: "restrict-access" },
    trustTransition: {
      score: 49,
      band: "medium",
      transition: "deteriorated",
      criticalOverride: null,
    },
  }));

  assert.equal(result.severity, "low-trust");
  assert.deepEqual(result.actionTypes, ["restrict-access"]);
  assert.equal(result.revocationAuthorized, false);
  assert.equal(result.scoreOnlyCanRevoke, false);
});

test("never revokes for a score decrease alone, including a fall to zero", () => {
  const result = evaluateSecurityActionTriggers(triggerInput({
    policyDecision: { outcome: "QUARANTINE", quarantineActionType: "suspend-subject" },
    trustTransition: {
      score: 0,
      band: "low",
      transition: "deteriorated",
      criticalOverride: null,
    },
  }));

  assert.deepEqual(result.actionTypes, ["suspend-subject"]);
  assert.equal(result.revocationAuthorized, false);
  assert.equal(result.reasonCode, "POLICY_QUARANTINE");
});

test("blocks renewal for one fresh severe signal while awaiting corroboration", () => {
  const result = evaluateSecurityActionTriggers(triggerInput({
    severeEvidence: [evidence()],
  }));

  assert.equal(result.severity, "severe-pending-corroboration");
  assert.deepEqual(result.actionTypes, ["block-renewal"]);
  assert.equal(result.revocationAuthorized, false);
  assert.equal(result.corroboration.enoughSources, false);
});

test("does not treat repeated sources or one repeated critical kind as corroboration", () => {
  const repeatedSource = evaluateSecurityActionTriggers(triggerInput({
    severeEvidence: [
      evidence(),
      evidence({
        evidenceId: "evd_018f1234-5678-7abc-8def-0123456789d1",
        kind: "device-compromised",
        componentId: "device",
      }),
    ],
  }));
  const repeatedKind = evaluateSecurityActionTriggers(triggerInput({
    severeEvidence: [
      evidence(),
      evidence({
        evidenceId: "evd_018f1234-5678-7abc-8def-0123456789d1",
        sourceId: SOURCE_B,
      }),
    ],
  }));

  assert.equal(repeatedSource.corroboration.enoughSources, false);
  assert.equal(repeatedKind.corroboration.enoughKinds, false);
  assert.equal(repeatedSource.revocationAuthorized, false);
  assert.equal(repeatedKind.revocationAuthorized, false);
});

test("authorizes revocation only for fresh independent evidence confirmed by critical trust", () => {
  const result = evaluateSecurityActionTriggers(triggerInput({
    policyDecision: { outcome: "QUARANTINE", quarantineActionType: "restrict-access" },
    trustTransition: {
      score: 20,
      band: "low",
      transition: "critical-override",
      criticalOverride: { kind: "identity-compromised", componentId: "identity" },
    },
    severeEvidence: [
      evidence(),
      evidence({
        evidenceId: "evd_018f1234-5678-7abc-8def-0123456789d1",
        sourceId: SOURCE_B,
        kind: "device-compromised",
        componentId: "device",
      }),
    ],
  }));

  assert.equal(result.severity, "severe-corroborated");
  assert.deepEqual(result.actionTypes, ["revoke-certificate"]);
  assert.equal(result.revocationAuthorized, true);
  assert.equal(result.corroboration.trustConfirmed, true);
});

test("excludes terminal certificate-revoked evidence from recursive action triggers", () => {
  assert.deepEqual(
    SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.terminalNonTriggerKinds,
    ["certificate-revoked"],
  );
  assert.throws(
    () => evaluateSecurityActionTriggers(triggerInput({
      severeEvidence: [evidence({
        kind: "certificate-revoked",
        componentId: "certificate",
      })],
    })),
    (error) => error instanceof SecurityActionStateMachineError
      && error.reasonCode === "SEVERE_EVIDENCE_NOT_ACTIONABLE",
  );
});

test("rejects stale, cross-target and duplicate severe evidence", () => {
  for (const severeEvidence of [
    [evidence({ observedAt: "2026-10-22T11:59:59.000Z" })],
    [evidence({ target: OTHER_TARGET })],
    [evidence(), evidence()],
  ]) {
    assert.throws(
      () => evaluateSecurityActionTriggers(triggerInput({ severeEvidence })),
      (error) => error instanceof SecurityActionStateMachineError,
    );
  }
});

test("requires stronger trust recovery for suspension than restriction", () => {
  const restricted = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "restrict-access",
  }).state;
  const suspended = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "suspend-subject",
  }).state;
  const mediumCheckpoint = checkpoint({ score: 45, band: "medium" });

  assert.equal(evaluateSecurityActionRecovery(recoveryInput(restricted, {
    checkpoint: mediumCheckpoint,
  })).nextActionType, "restore-access");
  assert.equal(evaluateSecurityActionRecovery(recoveryInput(suspended, {
    checkpoint: mediumCheckpoint,
  })).reasonCode, "TRUST_RECOVERY_INCOMPLETE");
  assert.equal(evaluateSecurityActionRecovery(recoveryInput(suspended)).nextActionType, "restore-access");
});

test("keeps recovery governed and preserves permanent revocation", () => {
  const revoked = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "revoke-certificate",
  }).state;
  const unresolved = evaluateSecurityActionRecovery(recoveryInput(revoked, {
    severeCauseResolved: false,
  }));
  const replacement = evaluateSecurityActionRecovery(recoveryInput(revoked));

  assert.equal(unresolved.eligible, false);
  assert.equal(unresolved.reasonCode, "SEVERE_CAUSE_UNRESOLVED");
  assert.equal(replacement.nextActionType, "issue-replacement-certificate");
  assert.equal(replacement.authorizationRequired, "recovery-authorization");
  assert.equal(replacement.targetCertificateReactivated, false);

  const replacementIssued = transitionSecurityActionState({
    currentState: revoked,
    actionType: "issue-replacement-certificate",
  }).state;
  const restore = evaluateSecurityActionRecovery(recoveryInput(replacementIssued));
  assert.equal(restore.nextActionType, "restore-access");
  assert.equal(replacementIssued.targetCertificate, "revoked");
});

test("active severe evidence and incomplete trust evidence block recovery", () => {
  const restricted = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "restrict-access",
  }).state;
  const active = evaluateSecurityActionRecovery(recoveryInput(restricted, {
    activeSevereEvidence: [evidence()],
  }));
  const oneSource = evaluateSecurityActionRecovery(recoveryInput(restricted, {
    checkpoint: checkpoint({ sourceIds: [SOURCE_A] }),
  }));
  const held = evaluateSecurityActionRecovery(recoveryInput(restricted, {
    checkpoint: checkpoint({ transition: "held" }),
  }));

  assert.equal(active.reasonCode, "ACTIVE_SEVERE_EVIDENCE");
  assert.equal(oneSource.reasonCode, "TRUST_RECOVERY_INCOMPLETE");
  assert.equal(held.reasonCode, "TRUST_RECOVERY_INCOMPLETE");
});

test("publishes deeply immutable trigger and recovery decisions", () => {
  const triggers = evaluateSecurityActionTriggers(triggerInput());
  const recovery = evaluateSecurityActionRecovery(recoveryInput(INITIAL_SECURITY_ACTION_STATE));

  assert.ok(Object.isFrozen(SECURITY_ACTION_TRIGGER_POLICY));
  assert.ok(Object.isFrozen(SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.actionableKinds));
  assert.ok(Object.isFrozen(SECURITY_ACTION_RECOVERY_POLICY));
  assert.ok(Object.isFrozen(triggers));
  assert.ok(Object.isFrozen(triggers.corroboration));
  assert.ok(Object.isFrozen(recovery));
  assert.ok(Object.isFrozen(recovery.checkpoint));
});
