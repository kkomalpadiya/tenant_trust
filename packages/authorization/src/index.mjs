import { assertNoTenantSwitch } from "@tenant-trust/tenant-context";

export const TENANT_ROLES = Object.freeze([
  "tenant-member",
  "tenant-admin",
]);

export const AUTHORIZATION_MODE_IDS = Object.freeze({
  PKI_RBAC_BASELINE: "pki-rbac-baseline-v1",
});

export const ACTIONS = Object.freeze([
  "profile:read",
  "record:read",
  "record:write",
  "record:export",
  "tenant:admin",
]);

export const RESOURCE_TYPES = Object.freeze({
  "profile:read": "subject-profile",
  "record:read": "tenant-record",
  "record:write": "tenant-record",
  "record:export": "tenant-record-export",
  "tenant:admin": "tenant-administration",
});

export const RESOURCE_SENSITIVITY = Object.freeze({
  "profile:read": "confidential",
  "record:read": "confidential",
  "record:write": "confidential",
  "record:export": "sensitive",
  "tenant:admin": "critical",
});

const COMMON_CONTROLS = Object.freeze([
  "authenticated-certificate",
  "active-membership",
  "resource-scope",
]);

const SENSITIVE_CONTROLS = Object.freeze([
  ...COMMON_CONTROLS,
  "operation-policy",
  "bound-step-up",
  "audit-record",
]);

function rule(role, action, disposition, scope, requiredControls, reason) {
  return Object.freeze({
    role,
    action,
    resourceType: RESOURCE_TYPES[action],
    sensitivity: RESOURCE_SENSITIVITY[action],
    disposition,
    scope,
    requiredControls,
    reason,
  });
}

export const ROLE_ACTION_MATRIX = Object.freeze([
  rule("tenant-member", "profile:read", "allow", "self", COMMON_CONTROLS, "member-self-profile"),
  rule("tenant-member", "record:read", "allow", "owner", COMMON_CONTROLS, "member-owned-record"),
  rule("tenant-member", "record:write", "allow", "owner", COMMON_CONTROLS, "member-owned-record"),
  rule("tenant-member", "record:export", "deny", "none", SENSITIVE_CONTROLS, "role-not-eligible"),
  rule("tenant-member", "tenant:admin", "deny", "none", SENSITIVE_CONTROLS, "role-not-eligible"),
  rule("tenant-admin", "profile:read", "allow", "self", COMMON_CONTROLS, "admin-self-profile"),
  rule("tenant-admin", "record:read", "allow", "tenant", COMMON_CONTROLS, "admin-tenant-record"),
  rule("tenant-admin", "record:write", "allow", "tenant", COMMON_CONTROLS, "admin-tenant-record"),
  rule("tenant-admin", "record:export", "requires-controls", "tenant", SENSITIVE_CONTROLS, "sensitive-operation"),
  rule("tenant-admin", "tenant:admin", "requires-controls", "tenant", SENSITIVE_CONTROLS, "critical-operation"),
]);

const DEFAULT_DENIAL = Object.freeze({
  role: "none",
  action: "unknown",
  resourceType: "unknown",
  sensitivity: "restricted",
  disposition: "deny",
  scope: "none",
  requiredControls: Object.freeze([]),
  reason: "default-deny",
});

const ACTION_SET = new Set(ACTIONS);
const ROLE_PRECEDENCE = Object.freeze(["tenant-admin", "tenant-member"]);
const RULES = new Map(ROLE_ACTION_MATRIX.map((entry) => [`${entry.role}\u0000${entry.action}`, entry]));
const AUTHORIZATION_MODES = new WeakSet();

export const AUTHORIZATION_DENIAL = Object.freeze({
  statusCode: 403,
  code: "ACCESS_DENIED",
});

export class AuthorizationError extends Error {
  constructor(reasonCode) {
    super("Authorization denied.");
    this.name = "AuthorizationError";
    this.reasonCode = reasonCode;
  }
}

const PKI_RBAC_BASELINE_MODE = Object.freeze({
  modeId: AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE,
  certificatePolicy: "tenant-scoped-x509",
  rolePolicy: "role-action-matrix-v1",
  adaptiveTrustUsed: false,
});
AUTHORIZATION_MODES.add(PKI_RBAC_BASELINE_MODE);

export function selectAuthorizationMode(modeId) {
  if (modeId !== AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE) {
    throw new AuthorizationError("AUTHORIZATION_MODE_UNSUPPORTED");
  }
  return PKI_RBAC_BASELINE_MODE;
}

export function assertAuthorizationMode(mode) {
  if (!mode || typeof mode !== "object" || !AUTHORIZATION_MODES.has(mode)) {
    throw new AuthorizationError("AUTHORIZATION_MODE_INVALID");
  }
  return mode;
}

export function resolveRoleAction(context, action) {
  const trustedContext = assertNoTenantSwitch(context);
  if (!ACTION_SET.has(action)) return DEFAULT_DENIAL;

  for (const role of ROLE_PRECEDENCE) {
    if (!trustedContext.roles.includes(role)) continue;
    return RULES.get(`${role}\u0000${action}`) ?? DEFAULT_DENIAL;
  }

  return DEFAULT_DENIAL;
}

export function evaluateAuthorizationMode(mode, context, action) {
  const selectedMode = assertAuthorizationMode(mode);
  const trustedContext = assertNoTenantSwitch(context);
  if (trustedContext.authentication.source !== "mtls-certificate") {
    throw new AuthorizationError("CERTIFICATE_AUTHENTICATION_REQUIRED");
  }
  const eligibility = resolveRoleAction(trustedContext, action);
  return Object.freeze({
    modeId: selectedMode.modeId,
    certificatePolicy: selectedMode.certificatePolicy,
    rolePolicy: selectedMode.rolePolicy,
    adaptiveTrustUsed: false,
    outcome: eligibility.disposition,
    eligibility,
  });
}

export function assertBaselineActionAllowed(mode, context, action) {
  const decision = evaluateAuthorizationMode(mode, context, action);
  if (decision.outcome !== "allow") {
    throw new AuthorizationError(decision.eligibility.reason === "default-deny"
      ? "DEFAULT_DENY"
      : "ADDITIONAL_CONTROLS_REQUIRED");
  }
  return decision.eligibility;
}

export function authorizationSafeDenial(error) {
  if (!(error instanceof AuthorizationError)) throw error;
  return AUTHORIZATION_DENIAL;
}
