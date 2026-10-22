export const POLICY_OUTCOMES = Object.freeze([
  "ALLOW",
  "STEP_UP",
  "DENY",
  "QUARANTINE",
]);

export const SECURITY_ACTION_TYPES = Object.freeze([
  "restrict-access",
  "suspend-subject",
  "block-renewal",
  "revoke-certificate",
  "restore-access",
  "issue-replacement-certificate",
]);

export const POLICY_OUTCOME_ACTION_MAPPING = Object.freeze({
  ALLOW: Object.freeze([]),
  STEP_UP: Object.freeze([]),
  DENY: Object.freeze([]),
  QUARANTINE: Object.freeze(["restrict-access", "suspend-subject"]),
});

function action(id, authority, reversible, effect) {
  return Object.freeze({ id, authority, reversible, effect: Object.freeze(effect) });
}

export const SECURITY_ACTION_DEFINITIONS = Object.freeze([
  action("restrict-access", "policy-quarantine", true, {
    access: "restricted",
    renewal: "unchanged",
    targetCertificate: "unchanged",
    replacement: "unchanged",
  }),
  action("suspend-subject", "policy-quarantine", true, {
    access: "suspended",
    renewal: "blocked",
    targetCertificate: "unchanged",
    replacement: "unchanged",
  }),
  action("block-renewal", "severity-rule", true, {
    access: "unchanged",
    renewal: "blocked",
    targetCertificate: "unchanged",
    replacement: "unchanged",
  }),
  action("revoke-certificate", "severity-rule", false, {
    access: "suspended",
    renewal: "blocked",
    targetCertificate: "revoked",
    replacement: "required",
  }),
  action("restore-access", "recovery-authorization", true, {
    access: "normal",
    renewal: "allowed",
    targetCertificate: "unchanged",
    replacement: "unchanged",
  }),
  action("issue-replacement-certificate", "recovery-authorization", false, {
    access: "unchanged",
    renewal: "unchanged",
    targetCertificate: "revoked",
    replacement: "issued",
  }),
]);

export const INITIAL_SECURITY_ACTION_STATE = Object.freeze({
  access: "normal",
  renewal: "allowed",
  targetCertificate: "active",
  replacement: "not-required",
});

const POLICY_OUTCOME_SET = new Set(POLICY_OUTCOMES);
const SECURITY_ACTION_DEFINITION_BY_ID = new Map(
  SECURITY_ACTION_DEFINITIONS.map((definition) => [definition.id, definition]),
);
const ACCESS_STATES = new Set(["normal", "restricted", "suspended"]);
const RENEWAL_STATES = new Set(["allowed", "blocked"]);
const CERTIFICATE_STATES = new Set(["active", "revoked"]);
const REPLACEMENT_STATES = new Set(["not-required", "required", "issued"]);
const STATE_KEYS = new Set(["access", "renewal", "targetCertificate", "replacement"]);
const POLICY_MAPPING_KEYS = new Set(["outcome", "quarantineActionType"]);
const TRANSITION_KEYS = new Set(["currentState", "actionType"]);

export class SecurityActionStateMachineError extends Error {
  constructor(reasonCode) {
    super("Security action state transition is invalid.");
    this.name = "SecurityActionStateMachineError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new SecurityActionStateMachineError(reasonCode);
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasOnlyKeys(value, allowedKeys) {
  return isPlainObject(value) && Object.keys(value).every((key) => allowedKeys.has(key));
}

function statesEqual(left, right) {
  return [...STATE_KEYS].every((key) => left[key] === right[key]);
}

export function defineSecurityActionState(state = INITIAL_SECURITY_ACTION_STATE) {
  if (!isPlainObject(state)
    || Object.keys(state).length !== STATE_KEYS.size
    || !Object.keys(state).every((key) => STATE_KEYS.has(key))
    || !ACCESS_STATES.has(state.access)
    || !RENEWAL_STATES.has(state.renewal)
    || !CERTIFICATE_STATES.has(state.targetCertificate)
    || !REPLACEMENT_STATES.has(state.replacement)) {
    fail("SECURITY_ACTION_STATE_INVALID");
  }
  if (state.access === "suspended" && state.renewal !== "blocked") {
    fail("SUSPENDED_RENEWAL_MUST_BE_BLOCKED");
  }
  if (state.targetCertificate === "active" && state.replacement !== "not-required") {
    fail("ACTIVE_CERTIFICATE_REPLACEMENT_INVALID");
  }
  if (state.targetCertificate === "revoked" && state.replacement === "not-required") {
    fail("REVOKED_CERTIFICATE_REPLACEMENT_REQUIRED");
  }
  if (state.targetCertificate === "revoked"
    && state.replacement === "required"
    && (state.access !== "suspended" || state.renewal !== "blocked")) {
    fail("REVOKED_CERTIFICATE_RECOVERY_INCOMPLETE");
  }
  return Object.freeze({
    access: state.access,
    renewal: state.renewal,
    targetCertificate: state.targetCertificate,
    replacement: state.replacement,
  });
}

export function getSecurityActionDefinition(actionType) {
  const definition = SECURITY_ACTION_DEFINITION_BY_ID.get(actionType);
  if (!definition) fail("SECURITY_ACTION_TYPE_UNKNOWN");
  return definition;
}

export function mapPolicyOutcomeToSecurityAction(input = {}) {
  if (!hasOnlyKeys(input, POLICY_MAPPING_KEYS)
    || !Object.hasOwn(input, "outcome")
    || !POLICY_OUTCOME_SET.has(input.outcome)) {
    fail("POLICY_OUTCOME_INVALID");
  }
  if (input.outcome !== "QUARANTINE") {
    if (input.quarantineActionType !== undefined && input.quarantineActionType !== null) {
      fail("POLICY_ACTION_NOT_ALLOWED");
    }
    return null;
  }
  if (!POLICY_OUTCOME_ACTION_MAPPING.QUARANTINE.includes(input.quarantineActionType)) {
    fail("QUARANTINE_ACTION_INVALID");
  }
  return Object.freeze({
    source: "policy-quarantine",
    outcome: input.outcome,
    actionType: input.quarantineActionType,
    reversible: true,
  });
}

export function transitionSecurityActionState(input = {}) {
  if (!isPlainObject(input)
    || Object.keys(input).length !== TRANSITION_KEYS.size
    || !Object.keys(input).every((key) => TRANSITION_KEYS.has(key))) {
    fail("SECURITY_ACTION_TRANSITION_INVALID");
  }
  const currentState = defineSecurityActionState(input.currentState);
  const definition = getSecurityActionDefinition(input.actionType);
  let nextState;
  switch (definition.id) {
    case "restrict-access":
      nextState = {
        ...currentState,
        access: currentState.access === "normal" ? "restricted" : currentState.access,
      };
      break;
    case "suspend-subject":
      nextState = { ...currentState, access: "suspended", renewal: "blocked" };
      break;
    case "block-renewal":
      nextState = { ...currentState, renewal: "blocked" };
      break;
    case "revoke-certificate":
      nextState = currentState.targetCertificate === "revoked"
        ? currentState
        : {
            access: "suspended",
            renewal: "blocked",
            targetCertificate: "revoked",
            replacement: "required",
          };
      break;
    case "issue-replacement-certificate":
      if (currentState.targetCertificate !== "revoked") fail("REPLACEMENT_NOT_REQUIRED");
      nextState = { ...currentState, replacement: "issued" };
      break;
    case "restore-access":
      if (currentState.targetCertificate === "revoked" && currentState.replacement !== "issued") {
        fail("REPLACEMENT_REQUIRED_BEFORE_RECOVERY");
      }
      nextState = { ...currentState, access: "normal", renewal: "allowed" };
      break;
    default:
      fail("SECURITY_ACTION_TYPE_UNKNOWN");
  }
  const state = defineSecurityActionState(nextState);
  return Object.freeze({
    actionType: definition.id,
    authority: definition.authority,
    reversible: definition.reversible,
    changed: !statesEqual(currentState, state),
    targetCertificateReactivated: false,
    state,
  });
}
