import assert from "node:assert/strict";
import {
  INITIAL_SECURITY_ACTION_STATE,
  SECURITY_ACTION_RECOVERY_POLICY,
  evaluateSecurityActionRecovery,
  evaluateSecurityActionTriggers,
  transitionSecurityActionState,
} from "../services/orchestrator/src/index.mjs";
import { DEFAULT_TRUST_TRANSITION_CONFIGURATION } from "../services/trust/src/index.mjs";

const target = {
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789a0",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789b0",
};
const evaluatedAt = "2026-10-22T12:05:00.000Z";
const sourceA = "src_018f1234-5678-7abc-8def-0123456789c0";
const sourceB = "src_018f1234-5678-7abc-8def-0123456789c1";

function severeEvidence(evidenceId, sourceId, kind, componentId) {
  return {
    evidenceId,
    sourceId,
    ...target,
    kind,
    componentId,
    observedAt: "2026-10-22T12:04:00.000Z",
  };
}

assert.equal(
  SECURITY_ACTION_RECOVERY_POLICY.requiredDistinctSources,
  DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.distinctSourceCount,
);
assert.equal(
  SECURITY_ACTION_RECOVERY_POLICY.requiredConsecutiveQualifyingEvaluations,
  DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations,
);
console.log("PASS recovery rules inherit the T6.6 source and evaluation requirements");

const scoreOnly = evaluateSecurityActionTriggers({
  target,
  policyDecision: { outcome: "QUARANTINE", quarantineActionType: "restrict-access" },
  trustTransition: {
    score: 0,
    band: "low",
    transition: "deteriorated",
    criticalOverride: null,
  },
  severeEvidence: [],
  evaluatedAt,
});
assert.deepEqual(scoreOnly.actionTypes, ["restrict-access"]);
assert.equal(scoreOnly.revocationAuthorized, false);
console.log("PASS a score decrease alone can restrict but can never revoke");

const corroborated = evaluateSecurityActionTriggers({
  target,
  policyDecision: { outcome: "QUARANTINE", quarantineActionType: "restrict-access" },
  trustTransition: {
    score: 20,
    band: "low",
    transition: "critical-override",
    criticalOverride: { kind: "identity-compromised", componentId: "identity" },
  },
  severeEvidence: [
    severeEvidence(
      "evd_018f1234-5678-7abc-8def-0123456789d0",
      sourceA,
      "identity-compromised",
      "identity",
    ),
    severeEvidence(
      "evd_018f1234-5678-7abc-8def-0123456789d1",
      sourceB,
      "device-compromised",
      "device",
    ),
  ],
  evaluatedAt,
});
assert.deepEqual(corroborated.actionTypes, ["revoke-certificate"]);
assert.equal(corroborated.revocationAuthorized, true);
console.log("PASS independent fresh severe evidence plus critical trust authorizes revocation");

const revoked = transitionSecurityActionState({
  currentState: INITIAL_SECURITY_ACTION_STATE,
  actionType: "revoke-certificate",
}).state;
const replacement = evaluateSecurityActionRecovery({
  target,
  currentState: revoked,
  checkpoint: {
    score: DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.recoveryThreshold,
    band: "high",
    transition: "recovered",
    consecutiveQualifyingEvaluations:
      DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations,
    sourceIds: [sourceA, sourceB],
  },
  activeSevereEvidence: [],
  evaluatedAt,
  severeCauseResolved: true,
});
assert.equal(replacement.nextActionType, "issue-replacement-certificate");
assert.equal(replacement.targetCertificateReactivated, false);
assert.equal(replacement.authorizationRequired, "recovery-authorization");
console.log("PASS governed recovery requires replacement and never reactivates the revoked target");
