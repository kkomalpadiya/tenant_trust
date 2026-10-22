import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  INITIAL_SECURITY_ACTION_STATE,
  POLICY_OUTCOME_ACTION_MAPPING,
  POLICY_OUTCOMES,
  SECURITY_ACTION_TYPES,
  SecurityActionStateMachineError,
  mapPolicyOutcomeToSecurityAction,
  transitionSecurityActionState,
} from "../services/orchestrator/src/index.mjs";

const actionSchema = JSON.parse(readFileSync(
  new URL("../packages/contracts/schemas/events/action-event.schema.json", import.meta.url),
  "utf8",
));
const decisionSchema = JSON.parse(readFileSync(
  new URL("../packages/contracts/schemas/policy/opa-decision-output.schema.json", import.meta.url),
  "utf8",
));

assert.deepEqual(decisionSchema.properties.outcome.enum, POLICY_OUTCOMES);
assert.deepEqual(
  decisionSchema.$defs.quarantineObligation.properties.actionType.enum,
  POLICY_OUTCOME_ACTION_MAPPING.QUARANTINE,
);
assert.deepEqual(actionSchema.allOf[1].properties.payload.properties.actionType.enum, SECURITY_ACTION_TYPES);
console.log("PASS policy outcomes and action types match the shared contracts");

for (const outcome of ["ALLOW", "STEP_UP", "DENY"]) {
  assert.equal(mapPolicyOutcomeToSecurityAction({ outcome }), null);
}
assert.equal(mapPolicyOutcomeToSecurityAction({
  outcome: "QUARANTINE",
  quarantineActionType: "restrict-access",
}).actionType, "restrict-access");
assert.equal(mapPolicyOutcomeToSecurityAction({
  outcome: "QUARANTINE",
  quarantineActionType: "suspend-subject",
}).actionType, "suspend-subject");
console.log("PASS only explicit QUARANTINE obligations map directly to reversible actions");

for (const actionType of ["revoke-certificate", "block-renewal", "restore-access"]) {
  assert.throws(
    () => mapPolicyOutcomeToSecurityAction({ outcome: "QUARANTINE", quarantineActionType: actionType }),
    (error) => error instanceof SecurityActionStateMachineError,
  );
}
console.log("PASS escalation and recovery actions require separate governed rules");

const restricted = transitionSecurityActionState({
  currentState: INITIAL_SECURITY_ACTION_STATE,
  actionType: "restrict-access",
});
const suspended = transitionSecurityActionState({
  currentState: restricted.state,
  actionType: "suspend-subject",
});
const restored = transitionSecurityActionState({
  currentState: suspended.state,
  actionType: "restore-access",
});
assert.deepEqual(restored.state, INITIAL_SECURITY_ACTION_STATE);
console.log("PASS restriction, suspension and renewal blocking support explicit recovery");

const revoked = transitionSecurityActionState({
  currentState: INITIAL_SECURITY_ACTION_STATE,
  actionType: "revoke-certificate",
});
assert.throws(
  () => transitionSecurityActionState({ currentState: revoked.state, actionType: "restore-access" }),
  (error) => error.reasonCode === "REPLACEMENT_REQUIRED_BEFORE_RECOVERY",
);
const replacement = transitionSecurityActionState({
  currentState: revoked.state,
  actionType: "issue-replacement-certificate",
});
const recovered = transitionSecurityActionState({
  currentState: replacement.state,
  actionType: "restore-access",
});
assert.equal(recovered.state.targetCertificate, "revoked");
assert.equal(recovered.state.replacement, "issued");
assert.equal(recovered.targetCertificateReactivated, false);
console.log("PASS revocation is irreversible and recovery uses a distinct replacement certificate");
