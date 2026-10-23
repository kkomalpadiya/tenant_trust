import {
  CRITICAL_EVIDENCE_OVERRIDE_RULES,
  DEFAULT_TRUST_TRANSITION_CONFIGURATION,
} from "@tenant-trust/trust";
import { createSecurityActionWorker as createSecurityActionWorkerBase } from "./action-orchestration.mjs";
import { createGovernedRecoveryService as createGovernedRecoveryServiceBase } from "./governed-recovery.mjs";

export {
  SECURITY_ACTION_ORCHESTRATION_POLICY,
  SecurityActionOrchestrationError,
  createPostgresSecurityActionRepository,
  createSecurityActionExecutor,
} from "./action-orchestration.mjs";

export {
  SECURITY_ACTION_OPERATIONS_POLICY,
  SecurityActionOperationsError,
  createPostgresSecurityActionOperationsRepository,
  createSecurityActionOperationsMonitor,
} from "./action-operations.mjs";

export {
  SECURITY_STATE_INVALIDATION_POLICY,
  SecurityStateInvalidationError,
  createPostgresSecurityStateInvalidationRepository,
  createRedisSecurityStateStore,
  createSecurityStateInvalidationWorker,
  securitySessionRedisKey,
  securityStateRedisKeys,
  subjectSecurityCacheRedisKey,
} from "./security-state-invalidation.mjs";

export {
  GOVERNED_RECOVERY_POLICY,
  GovernedRecoveryError,
  createPostgresGovernedRecoveryRepository,
} from "./governed-recovery.mjs";

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
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SOURCE_ID = /^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRUST_BANDS = new Set(["low", "medium", "high"]);
const TRUST_TRANSITIONS = new Set(["held", "deteriorated", "recovered", "critical-override"]);
const TRIGGER_INPUT_KEYS = new Set([
  "target",
  "policyDecision",
  "trustTransition",
  "severeEvidence",
  "evaluatedAt",
]);
const TARGET_KEYS = new Set(["tenantId", "subjectId"]);
const TRUST_TRANSITION_KEYS = new Set(["score", "band", "transition", "criticalOverride"]);
const CRITICAL_OVERRIDE_KEYS = new Set(["kind", "componentId"]);
const SEVERE_EVIDENCE_KEYS = new Set([
  "evidenceId",
  "sourceId",
  "tenantId",
  "subjectId",
  "kind",
  "componentId",
  "observedAt",
]);
const RECOVERY_INPUT_KEYS = new Set([
  "target",
  "currentState",
  "checkpoint",
  "activeSevereEvidence",
  "evaluatedAt",
  "severeCauseResolved",
]);
const RECOVERY_CHECKPOINT_KEYS = new Set([
  "score",
  "band",
  "transition",
  "consecutiveQualifyingEvaluations",
  "sourceIds",
]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

const ACTIONABLE_SEVERE_EVIDENCE = Object.fromEntries(
  Object.entries(CRITICAL_EVIDENCE_OVERRIDE_RULES)
    .filter(([kind]) => kind !== "certificate-revoked")
    .map(([kind, rule]) => [kind, {
      componentId: rule.componentId,
      scoreCeiling: rule.scoreCeiling,
    }]),
);

export const SECURITY_ACTION_TRIGGER_POLICY = deepFreeze({
  policyQuarantine: {
    severity: "low-trust",
    actions: [...POLICY_OUTCOME_ACTION_MAPPING.QUARANTINE],
    reversibleOnly: true,
  },
  severeEvidence: {
    actionableKinds: ACTIONABLE_SEVERE_EVIDENCE,
    terminalNonTriggerKinds: ["certificate-revoked"],
    maximumAgeSeconds: 300,
    requiredDistinctSourcesForRevocation: 2,
    requiredDistinctKindsForRevocation: 2,
    pendingAction: "block-renewal",
    corroboratedAction: "revoke-certificate",
    requireLowCriticalTrustTransition: true,
    scoreOnlyCanRevoke: false,
  },
});

export const SECURITY_ACTION_RECOVERY_POLICY = deepFreeze({
  authorizationClass: "recovery-authorization",
  requireNoActiveSevereEvidence: true,
  requireResolvedCauseForReplacement: true,
  requireRecoveredTrustTransition: true,
  restricted: {
    minimumBand: "medium",
    minimumScore: DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.low.recoveryThreshold,
  },
  suspendedOrRenewalBlocked: {
    minimumBand: "high",
    minimumScore: DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.recoveryThreshold,
  },
  revoked: {
    minimumBand: "high",
    minimumScore: DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.recoveryThreshold,
    targetCertificateReactivated: false,
  },
  requiredDistinctSources:
    DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.distinctSourceCount,
  requiredConsecutiveQualifyingEvaluations:
    DEFAULT_TRUST_TRANSITION_CONFIGURATION.recovery.consecutiveQualifyingEvaluations,
});

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

function hasExactKeys(value, expectedKeys) {
  return isPlainObject(value)
    && Object.keys(value).length === expectedKeys.size
    && Object.keys(value).every((key) => expectedKeys.has(key));
}

function canonicalUtc(value) {
  if (typeof value !== "string" || !value.endsWith("Z")) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function validScore(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
}

function normalizeTarget(value) {
  if (!hasExactKeys(value, TARGET_KEYS)
    || !TENANT_ID.test(value.tenantId ?? "")
    || !SUBJECT_ID.test(value.subjectId ?? "")) {
    fail("SECURITY_ACTION_TARGET_INVALID");
  }
  return Object.freeze({ tenantId: value.tenantId, subjectId: value.subjectId });
}

function normalizeCriticalOverride(value) {
  if (value === null) return null;
  if (!hasExactKeys(value, CRITICAL_OVERRIDE_KEYS)) fail("TRUST_TRANSITION_INVALID");
  const rule = CRITICAL_EVIDENCE_OVERRIDE_RULES[value.kind];
  if (!rule || rule.componentId !== value.componentId) fail("TRUST_TRANSITION_INVALID");
  return Object.freeze({ kind: value.kind, componentId: value.componentId, rule });
}

function normalizeTrustTransition(value) {
  if (!hasExactKeys(value, TRUST_TRANSITION_KEYS)
    || !validScore(value.score)
    || !TRUST_BANDS.has(value.band)
    || !TRUST_TRANSITIONS.has(value.transition)) {
    fail("TRUST_TRANSITION_INVALID");
  }
  const criticalOverride = normalizeCriticalOverride(value.criticalOverride);
  if ((value.transition === "critical-override") !== (criticalOverride !== null)) {
    fail("TRUST_TRANSITION_INVALID");
  }
  if ((value.band === "high"
      && value.score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.high.deteriorationThreshold)
    || (value.band === "medium"
      && value.score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.deteriorationThreshold)
    || (criticalOverride !== null
      && (value.band !== criticalOverride.rule.forcedBand
        || value.score > criticalOverride.rule.scoreCeiling))) {
    fail("TRUST_TRANSITION_INVALID");
  }
  return Object.freeze({
    score: value.score,
    band: value.band,
    transition: value.transition,
    criticalOverride,
  });
}

function normalizeSevereEvidence(value, target, evaluatedAt) {
  if (!Array.isArray(value)) fail("SEVERE_EVIDENCE_INVALID");
  const evaluatedTime = new Date(evaluatedAt).getTime();
  const evidence = value.map((entry) => {
    if (!hasExactKeys(entry, SEVERE_EVIDENCE_KEYS)
      || !EVIDENCE_ID.test(entry.evidenceId ?? "")
      || !SOURCE_ID.test(entry.sourceId ?? "")
      || entry.tenantId !== target.tenantId
      || entry.subjectId !== target.subjectId
      || !canonicalUtc(entry.observedAt)) {
      fail("SEVERE_EVIDENCE_INVALID");
    }
    const rule = SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.actionableKinds[entry.kind];
    if (!rule || rule.componentId !== entry.componentId) fail("SEVERE_EVIDENCE_NOT_ACTIONABLE");
    const ageSeconds = (evaluatedTime - new Date(entry.observedAt).getTime()) / 1000;
    if (ageSeconds < 0 || ageSeconds > SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.maximumAgeSeconds) {
      fail("SEVERE_EVIDENCE_STALE");
    }
    return Object.freeze({ ...entry });
  });
  if (new Set(evidence.map(({ evidenceId }) => evidenceId)).size !== evidence.length) {
    fail("SEVERE_EVIDENCE_DUPLICATE");
  }
  return Object.freeze(evidence);
}

function normalizePolicyDecision(value) {
  if (!isPlainObject(value)) fail("POLICY_OUTCOME_INVALID");
  return mapPolicyOutcomeToSecurityAction(value);
}

function summarizeSevereEvidence(evidence) {
  return {
    evidenceIds: [...evidence.map(({ evidenceId }) => evidenceId)].sort(),
    sourceIds: [...new Set(evidence.map(({ sourceId }) => sourceId))].sort(),
    kinds: [...new Set(evidence.map(({ kind }) => kind))].sort(),
  };
}

function trustConfirmsSevereEvidence(trustTransition, severeKinds) {
  return trustTransition.band === "low"
    && trustTransition.transition === "critical-override"
    && trustTransition.criticalOverride !== null
    && severeKinds.includes(trustTransition.criticalOverride.kind)
    && trustTransition.score <= ACTIONABLE_SEVERE_EVIDENCE[
      trustTransition.criticalOverride.kind
    ].scoreCeiling;
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

export function evaluateSecurityActionTriggers(input = {}) {
  if (!hasExactKeys(input, TRIGGER_INPUT_KEYS) || !canonicalUtc(input.evaluatedAt)) {
    fail("SECURITY_ACTION_TRIGGER_INPUT_INVALID");
  }
  const target = normalizeTarget(input.target);
  const policyAction = normalizePolicyDecision(input.policyDecision);
  const trustTransition = normalizeTrustTransition(input.trustTransition);
  const severeEvidence = normalizeSevereEvidence(
    input.severeEvidence,
    target,
    input.evaluatedAt,
  );
  const summary = summarizeSevereEvidence(severeEvidence);
  const enoughSources = summary.sourceIds.length
    >= SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.requiredDistinctSourcesForRevocation;
  const enoughKinds = summary.kinds.length
    >= SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.requiredDistinctKindsForRevocation;
  const trustConfirmed = trustConfirmsSevereEvidence(trustTransition, summary.kinds);
  const revocationAuthorized = enoughSources && enoughKinds && trustConfirmed;

  let severity = "none";
  let actionTypes = [];
  let reasonCode = "NO_DURABLE_ACTION";
  if (revocationAuthorized) {
    severity = "severe-corroborated";
    actionTypes = [SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.corroboratedAction];
    reasonCode = "CORROBORATED_SEVERE_EVIDENCE";
  } else if (severeEvidence.length > 0) {
    severity = "severe-pending-corroboration";
    actionTypes = policyAction ? [policyAction.actionType] : [];
    if (policyAction?.actionType !== "suspend-subject") {
      actionTypes.push(SECURITY_ACTION_TRIGGER_POLICY.severeEvidence.pendingAction);
    }
    reasonCode = "SEVERE_EVIDENCE_NOT_CORROBORATED";
  } else if (policyAction) {
    severity = SECURITY_ACTION_TRIGGER_POLICY.policyQuarantine.severity;
    actionTypes = [policyAction.actionType];
    reasonCode = "POLICY_QUARANTINE";
  }

  return deepFreeze({
    target,
    severity,
    actionTypes,
    reasonCode,
    revocationAuthorized,
    scoreOnlyCanRevoke: false,
    corroboration: {
      evidenceIds: summary.evidenceIds,
      sourceIds: summary.sourceIds,
      kinds: summary.kinds,
      enoughSources,
      enoughKinds,
      trustConfirmed,
    },
  });
}

function normalizeRecoveryCheckpoint(value) {
  if (!hasExactKeys(value, RECOVERY_CHECKPOINT_KEYS)
    || !validScore(value.score)
    || !TRUST_BANDS.has(value.band)
    || !TRUST_TRANSITIONS.has(value.transition)
    || !Number.isSafeInteger(value.consecutiveQualifyingEvaluations)
    || value.consecutiveQualifyingEvaluations < 0
    || !Array.isArray(value.sourceIds)
    || value.sourceIds.some((sourceId) => !SOURCE_ID.test(sourceId))
    || new Set(value.sourceIds).size !== value.sourceIds.length) {
    fail("RECOVERY_CHECKPOINT_INVALID");
  }
  if (value.transition === "recovered"
    && (value.band === "low"
      || (value.band === "medium"
        && value.score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.low.recoveryThreshold)
      || (value.band === "high"
        && value.score < DEFAULT_TRUST_TRANSITION_CONFIGURATION.bands.medium.recoveryThreshold))) {
    fail("RECOVERY_CHECKPOINT_INVALID");
  }
  return Object.freeze({
    score: value.score,
    band: value.band,
    transition: value.transition,
    consecutiveQualifyingEvaluations: value.consecutiveQualifyingEvaluations,
    sourceIds: Object.freeze([...value.sourceIds].sort()),
  });
}

function recoveryTrustReady(checkpoint, requirement) {
  const bandRank = { low: 0, medium: 1, high: 2 };
  return checkpoint.transition === "recovered"
    && bandRank[checkpoint.band] >= bandRank[requirement.minimumBand]
    && checkpoint.score >= requirement.minimumScore
    && checkpoint.consecutiveQualifyingEvaluations
      >= SECURITY_ACTION_RECOVERY_POLICY.requiredConsecutiveQualifyingEvaluations
    && checkpoint.sourceIds.length
      >= SECURITY_ACTION_RECOVERY_POLICY.requiredDistinctSources;
}

export function evaluateSecurityActionRecovery(input = {}) {
  if (!hasExactKeys(input, RECOVERY_INPUT_KEYS)
    || !canonicalUtc(input.evaluatedAt)
    || typeof input.severeCauseResolved !== "boolean") {
    fail("SECURITY_ACTION_RECOVERY_INPUT_INVALID");
  }
  const target = normalizeTarget(input.target);
  const currentState = defineSecurityActionState(input.currentState);
  const checkpoint = normalizeRecoveryCheckpoint(input.checkpoint);
  const activeSevereEvidence = normalizeSevereEvidence(
    input.activeSevereEvidence,
    target,
    input.evaluatedAt,
  );

  let requirement = SECURITY_ACTION_RECOVERY_POLICY.restricted;
  if (currentState.targetCertificate === "revoked") {
    requirement = SECURITY_ACTION_RECOVERY_POLICY.revoked;
  } else if (currentState.access === "suspended" || currentState.renewal === "blocked") {
    requirement = SECURITY_ACTION_RECOVERY_POLICY.suspendedOrRenewalBlocked;
  }

  let nextActionType = null;
  let reasonCode = "NO_RECOVERY_NEEDED";
  const recoveryNeeded = currentState.targetCertificate === "revoked"
    || currentState.access !== "normal"
    || currentState.renewal !== "allowed";
  if (!recoveryNeeded) {
    reasonCode = "NO_RECOVERY_NEEDED";
  } else if (activeSevereEvidence.length > 0) {
    reasonCode = "ACTIVE_SEVERE_EVIDENCE";
  } else if (!recoveryTrustReady(checkpoint, requirement)) {
    reasonCode = "TRUST_RECOVERY_INCOMPLETE";
  } else if (currentState.targetCertificate === "revoked" && !input.severeCauseResolved) {
    reasonCode = "SEVERE_CAUSE_UNRESOLVED";
  } else if (currentState.targetCertificate === "revoked"
    && currentState.replacement === "required") {
    nextActionType = "issue-replacement-certificate";
    reasonCode = "REPLACEMENT_ELIGIBLE";
  } else if (currentState.access !== "normal" || currentState.renewal !== "allowed") {
    nextActionType = "restore-access";
    reasonCode = "ACCESS_RECOVERY_ELIGIBLE";
  }

  return deepFreeze({
    target,
    eligible: nextActionType !== null,
    nextActionType,
    reasonCode,
    authorizationRequired: SECURITY_ACTION_RECOVERY_POLICY.authorizationClass,
    targetCertificateReactivated: false,
    checkpoint,
  });
}

export function createSecurityActionWorker(options = {}) {
  return createSecurityActionWorkerBase({
    ...options,
    transitionState: transitionSecurityActionState,
  });
}

export function createGovernedRecoveryService(options = {}) {
  return createGovernedRecoveryServiceBase({
    ...options,
    evaluateRecovery: evaluateSecurityActionRecovery,
  });
}
