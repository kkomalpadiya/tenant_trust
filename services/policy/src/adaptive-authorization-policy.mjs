const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const PROFILE_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;

const ACTION_DEFINITIONS = Object.freeze({
  "profile:read": Object.freeze({ sensitivity: "confidential", allowedRoles: Object.freeze(["tenant-member", "tenant-admin"]), stepUpRequired: false }),
  "record:read": Object.freeze({ sensitivity: "confidential", allowedRoles: Object.freeze(["tenant-member", "tenant-admin"]), stepUpRequired: false }),
  "record:write": Object.freeze({ sensitivity: "confidential", allowedRoles: Object.freeze(["tenant-member", "tenant-admin"]), stepUpRequired: false }),
  "record:export": Object.freeze({ sensitivity: "sensitive", allowedRoles: Object.freeze(["tenant-admin"]), stepUpRequired: true }),
  "tenant:admin": Object.freeze({ sensitivity: "critical", allowedRoles: Object.freeze(["tenant-admin"]), stepUpRequired: true }),
  "member:manage": Object.freeze({ sensitivity: "critical", allowedRoles: Object.freeze(["tenant-admin"]), stepUpRequired: true }),
  "certificate:manage": Object.freeze({ sensitivity: "critical", allowedRoles: Object.freeze(["tenant-admin"]), stepUpRequired: true }),
  "admin-key:rotate": Object.freeze({ sensitivity: "critical", allowedRoles: Object.freeze(["tenant-admin"]), stepUpRequired: true }),
});

const DEFAULT_MINIMUM_SCORES = Object.freeze({
  "profile:read": 55,
  "record:read": 55,
  "record:write": 65,
  "record:export": 65,
  "tenant:admin": 80,
  "member:manage": 80,
  "certificate:manage": 80,
  "admin-key:rotate": 90,
});

const CONFIGURATION_FIELDS = Object.freeze([
  "actionRules",
  "calibrationStatus",
  "policyProfile",
  "quarantineAction",
  "schemaVersion",
  "scoreBands",
  "stepUpMaximumAgeSeconds",
  "tenantId",
]);

export const ADAPTIVE_AUTHORIZATION_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  policyProfile: "slide-14-prototype-v1",
  calibrationStatus: "unvalidated-prototype-defaults",
  scoreBands: Object.freeze({
    quarantineBelow: 50,
    restrictedBelow: 65,
    conditionalBelow: 80,
    maximum: 100,
  }),
  profileReadMinimumScore: 55,
  adminKeyRotationMinimumScore: 90,
  stepUpMaximumAgeSeconds: 300,
  quarantineAction: "restrict-access",
  actions: Object.freeze(Object.keys(ACTION_DEFINITIONS)),
});

export class AdaptiveAuthorizationPolicyError extends Error {
  constructor(reasonCode) {
    super("Adaptive authorization policy configuration is invalid.");
    this.name = "AdaptiveAuthorizationPolicyError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new AdaptiveAuthorizationPolicyError(reasonCode);
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function requireExactFields(value, fields, reasonCode) {
  if (!isPlainObject(value)) fail(reasonCode);
  const actual = Object.keys(value).sort();
  if (actual.length !== fields.length || actual.some((field, index) => field !== fields[index])) {
    fail(reasonCode);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function cloneJson(value) {
  try {
    return structuredClone(value);
  } catch {
    fail("POLICY_CONFIGURATION_INVALID");
  }
}

function validScore(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
}

function validateScoreBands(value) {
  const bands = requireExactFields(
    value,
    ["conditionalBelow", "maximum", "quarantineBelow", "restrictedBelow"],
    "POLICY_SCORE_BANDS_INVALID",
  );
  if (![bands.quarantineBelow, bands.restrictedBelow, bands.conditionalBelow, bands.maximum].every(validScore)
    || bands.quarantineBelow <= 0
    || bands.quarantineBelow >= bands.restrictedBelow
    || bands.restrictedBelow >= bands.conditionalBelow
    || bands.conditionalBelow >= bands.maximum
    || bands.maximum !== 100) {
    fail("POLICY_SCORE_BANDS_INVALID");
  }
}

function validateRoles(value, definition) {
  if (!Array.isArray(value) || value.length < 1 || value.length > definition.allowedRoles.length
    || new Set(value).size !== value.length
    || value.some((role) => !definition.allowedRoles.includes(role))) {
    fail("POLICY_ACTION_RULE_INVALID");
  }
}

function validateActionRules(value) {
  if (!Array.isArray(value) || value.length !== Object.keys(ACTION_DEFINITIONS).length) {
    fail("POLICY_ACTION_RULES_INVALID");
  }
  const seen = new Set();
  for (const rawRule of value) {
    const rule = requireExactFields(
      rawRule,
      ["action", "minimumScore", "roles", "sensitivity", "stepUpRequired"],
      "POLICY_ACTION_RULE_INVALID",
    );
    const definition = ACTION_DEFINITIONS[rule.action];
    if (!definition
      || seen.has(rule.action)
      || rule.sensitivity !== definition.sensitivity
      || !validScore(rule.minimumScore)
      || typeof rule.stepUpRequired !== "boolean"
      || (definition.stepUpRequired && rule.stepUpRequired !== true)) {
      fail("POLICY_ACTION_RULE_INVALID");
    }
    validateRoles(rule.roles, definition);
    seen.add(rule.action);
  }
}

export function validateAdaptiveAuthorizationPolicyData(value, expectedTenantId) {
  const data = requireExactFields(value, ["tenant_trust_policy"], "POLICY_DATA_INVALID");
  const root = requireExactFields(data.tenant_trust_policy, ["authorization"], "POLICY_DATA_INVALID");
  const authorization = requireExactFields(root.authorization, ["configuration"], "POLICY_DATA_INVALID");
  const configuration = requireExactFields(
    authorization.configuration,
    CONFIGURATION_FIELDS,
    "POLICY_CONFIGURATION_INVALID",
  );
  if (!TENANT_ID.test(expectedTenantId ?? "")
    || configuration.tenantId !== expectedTenantId
    || configuration.schemaVersion !== ADAPTIVE_AUTHORIZATION_POLICY.schemaVersion
    || !PROFILE_ID.test(configuration.policyProfile ?? "")
    || configuration.calibrationStatus !== ADAPTIVE_AUTHORIZATION_POLICY.calibrationStatus
    || configuration.quarantineAction !== ADAPTIVE_AUTHORIZATION_POLICY.quarantineAction
    || !Number.isSafeInteger(configuration.stepUpMaximumAgeSeconds)
    || configuration.stepUpMaximumAgeSeconds < 1
    || configuration.stepUpMaximumAgeSeconds > 900) {
    fail("POLICY_CONFIGURATION_INVALID");
  }
  validateScoreBands(configuration.scoreBands);
  validateActionRules(configuration.actionRules);
  return deepFreeze(cloneJson(data));
}

export function createSlide14PrototypePolicyData({ tenantId } = {}) {
  if (!TENANT_ID.test(tenantId ?? "")) fail("POLICY_TENANT_INVALID");
  const actionRules = Object.entries(ACTION_DEFINITIONS).map(([action, definition]) => ({
    action,
    sensitivity: definition.sensitivity,
    minimumScore: DEFAULT_MINIMUM_SCORES[action],
    roles: [...definition.allowedRoles],
    stepUpRequired: definition.stepUpRequired,
  }));
  return validateAdaptiveAuthorizationPolicyData({
    tenant_trust_policy: {
      authorization: {
        configuration: {
          schemaVersion: ADAPTIVE_AUTHORIZATION_POLICY.schemaVersion,
          policyProfile: ADAPTIVE_AUTHORIZATION_POLICY.policyProfile,
          calibrationStatus: ADAPTIVE_AUTHORIZATION_POLICY.calibrationStatus,
          tenantId,
          scoreBands: { ...ADAPTIVE_AUTHORIZATION_POLICY.scoreBands },
          actionRules,
          stepUpMaximumAgeSeconds: ADAPTIVE_AUTHORIZATION_POLICY.stepUpMaximumAgeSeconds,
          quarantineAction: ADAPTIVE_AUTHORIZATION_POLICY.quarantineAction,
        },
      },
    },
  }, tenantId);
}
