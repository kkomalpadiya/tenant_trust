import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  INITIAL_SECURITY_ACTION_STATE,
  POLICY_OUTCOME_ACTION_MAPPING,
  POLICY_OUTCOMES,
  SECURITY_ACTION_DEFINITIONS,
  SECURITY_ACTION_TYPES,
  SecurityActionStateMachineError,
  defineSecurityActionState,
  mapPolicyOutcomeToSecurityAction,
  transitionSecurityActionState,
} from "../src/index.mjs";

const actionSchemaPath = fileURLToPath(new URL(
  "../../../packages/contracts/schemas/events/action-event.schema.json",
  import.meta.url,
));
const decisionSchemaPath = fileURLToPath(new URL(
  "../../../packages/contracts/schemas/policy/opa-decision-output.schema.json",
  import.meta.url,
));

test("matches the shared decision and action contracts", () => {
  const actionSchema = JSON.parse(readFileSync(actionSchemaPath, "utf8"));
  const decisionSchema = JSON.parse(readFileSync(decisionSchemaPath, "utf8"));
  assert.deepEqual(decisionSchema.properties.outcome.enum, POLICY_OUTCOMES);
  assert.deepEqual(actionSchema.allOf[1].properties.payload.properties.actionType.enum, SECURITY_ACTION_TYPES);
  assert.deepEqual(
    decisionSchema.$defs.quarantineObligation.properties.actionType.enum,
    POLICY_OUTCOME_ACTION_MAPPING.QUARANTINE,
  );
});

test("maps only an explicit QUARANTINE obligation to immediate state actions", () => {
  for (const outcome of ["ALLOW", "STEP_UP", "DENY"]) {
    assert.equal(mapPolicyOutcomeToSecurityAction({ outcome }), null);
  }
  assert.deepEqual(mapPolicyOutcomeToSecurityAction({
    outcome: "QUARANTINE",
    quarantineActionType: "restrict-access",
  }), {
    source: "policy-quarantine",
    outcome: "QUARANTINE",
    actionType: "restrict-access",
    reversible: true,
  });
  assert.equal(mapPolicyOutcomeToSecurityAction({
    outcome: "QUARANTINE",
    quarantineActionType: "suspend-subject",
  }).actionType, "suspend-subject");
});

test("never infers escalation or recovery from a policy outcome alone", () => {
  for (const actionType of [
    "block-renewal",
    "revoke-certificate",
    "restore-access",
    "issue-replacement-certificate",
  ]) {
    assert.throws(
      () => mapPolicyOutcomeToSecurityAction({
        outcome: "QUARANTINE",
        quarantineActionType: actionType,
      }),
      (error) => error instanceof SecurityActionStateMachineError
        && error.reasonCode === "QUARANTINE_ACTION_INVALID",
    );
  }
  assert.throws(
    () => mapPolicyOutcomeToSecurityAction({
      outcome: "ALLOW",
      quarantineActionType: "restore-access",
    }),
    (error) => error.reasonCode === "POLICY_ACTION_NOT_ALLOWED",
  );
});

test("makes restriction and suspension reversible while suspension blocks renewal", () => {
  const restricted = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "restrict-access",
  });
  assert.deepEqual(restricted.state, {
    access: "restricted",
    renewal: "allowed",
    targetCertificate: "active",
    replacement: "not-required",
  });
  assert.equal(restricted.reversible, true);

  const suspended = transitionSecurityActionState({
    currentState: restricted.state,
    actionType: "suspend-subject",
  });
  assert.deepEqual(suspended.state, {
    access: "suspended",
    renewal: "blocked",
    targetCertificate: "active",
    replacement: "not-required",
  });

  const restored = transitionSecurityActionState({
    currentState: suspended.state,
    actionType: "restore-access",
  });
  assert.deepEqual(restored.state, INITIAL_SECURITY_ACTION_STATE);
});

test("supports a standalone reversible renewal block", () => {
  const blocked = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "block-renewal",
  });
  assert.deepEqual(blocked.state, {
    ...INITIAL_SECURITY_ACTION_STATE,
    renewal: "blocked",
  });
  assert.equal(blocked.authority, "severity-rule");

  const restored = transitionSecurityActionState({
    currentState: blocked.state,
    actionType: "restore-access",
  });
  assert.deepEqual(restored.state, INITIAL_SECURITY_ACTION_STATE);
});

test("makes certificate revocation irreversible and requires a fresh replacement", () => {
  const revoked = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "revoke-certificate",
  });
  assert.equal(revoked.reversible, false);
  assert.deepEqual(revoked.state, {
    access: "suspended",
    renewal: "blocked",
    targetCertificate: "revoked",
    replacement: "required",
  });

  assert.throws(
    () => transitionSecurityActionState({
      currentState: revoked.state,
      actionType: "restore-access",
    }),
    (error) => error.reasonCode === "REPLACEMENT_REQUIRED_BEFORE_RECOVERY",
  );

  const replacement = transitionSecurityActionState({
    currentState: revoked.state,
    actionType: "issue-replacement-certificate",
  });
  assert.equal(replacement.state.targetCertificate, "revoked");
  assert.equal(replacement.state.replacement, "issued");

  const restored = transitionSecurityActionState({
    currentState: replacement.state,
    actionType: "restore-access",
  });
  assert.deepEqual(restored.state, {
    access: "normal",
    renewal: "allowed",
    targetCertificate: "revoked",
    replacement: "issued",
  });
  assert.equal(restored.targetCertificateReactivated, false);
});

test("repeated actions are idempotent and stronger controls dominate weaker ones", () => {
  const suspended = transitionSecurityActionState({
    currentState: INITIAL_SECURITY_ACTION_STATE,
    actionType: "suspend-subject",
  });
  const repeated = transitionSecurityActionState({
    currentState: suspended.state,
    actionType: "suspend-subject",
  });
  const weaker = transitionSecurityActionState({
    currentState: suspended.state,
    actionType: "restrict-access",
  });
  assert.equal(repeated.changed, false);
  assert.equal(weaker.changed, false);
  assert.deepEqual(weaker.state, suspended.state);

  const revoked = transitionSecurityActionState({
    currentState: suspended.state,
    actionType: "revoke-certificate",
  });
  const repeatedRevocation = transitionSecurityActionState({
    currentState: revoked.state,
    actionType: "revoke-certificate",
  });
  assert.equal(repeatedRevocation.changed, false);
  assert.deepEqual(repeatedRevocation.state, revoked.state);
});

test("rejects impossible state combinations and unknown actions", () => {
  for (const state of [
    { ...INITIAL_SECURITY_ACTION_STATE, unexpected: true },
    { ...INITIAL_SECURITY_ACTION_STATE, access: "suspended" },
    { ...INITIAL_SECURITY_ACTION_STATE, targetCertificate: "revoked" },
    {
      access: "normal",
      renewal: "allowed",
      targetCertificate: "revoked",
      replacement: "required",
    },
  ]) {
    assert.throws(
      () => defineSecurityActionState(state),
      (error) => error instanceof SecurityActionStateMachineError,
    );
  }
  assert.throws(
    () => transitionSecurityActionState({
      currentState: INITIAL_SECURITY_ACTION_STATE,
      actionType: "reactivate-revoked-certificate",
    }),
    (error) => error.reasonCode === "SECURITY_ACTION_TYPE_UNKNOWN",
  );
  assert.throws(
    () => transitionSecurityActionState({
      currentState: INITIAL_SECURITY_ACTION_STATE,
      actionType: "issue-replacement-certificate",
    }),
    (error) => error.reasonCode === "REPLACEMENT_NOT_REQUIRED",
  );
});

test("publishes stable immutable definitions for every action type", () => {
  assert.deepEqual(SECURITY_ACTION_DEFINITIONS.map(({ id }) => id), SECURITY_ACTION_TYPES);
  assert.ok(Object.isFrozen(POLICY_OUTCOMES));
  assert.ok(Object.isFrozen(SECURITY_ACTION_TYPES));
  assert.ok(Object.isFrozen(POLICY_OUTCOME_ACTION_MAPPING));
  assert.ok(Object.values(POLICY_OUTCOME_ACTION_MAPPING).every(Object.isFrozen));
  assert.ok(Object.isFrozen(SECURITY_ACTION_DEFINITIONS));
  assert.ok(SECURITY_ACTION_DEFINITIONS.every((definition) => (
    Object.isFrozen(definition) && Object.isFrozen(definition.effect)
  )));
});
