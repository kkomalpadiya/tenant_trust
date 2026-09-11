const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const AUTHENTICATION_SOURCES = new Set(["mtls-certificate", "trusted-session"]);
const TENANT_ROLES = new Set(["tenant-admin", "tenant-member"]);
const CLAIM_SOURCES = new Set(["header", "path", "query", "body", "resource"]);
const RESOLVED_CONTEXTS = new WeakSet();

export const TENANT_CONTEXT_DENIAL = Object.freeze({
  statusCode: 403,
  code: "ACCESS_DENIED",
});

export class TenantContextError extends Error {
  constructor(reasonCode) {
    super("Tenant context resolution denied.");
    this.name = "TenantContextError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new TenantContextError(reasonCode);
}

function isPositiveVersion(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function requireRecord(value, reasonCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) deny(reasonCode);
  return value;
}

export function resolveTenantContext({ authentication, authority } = {}) {
  const trustedAuthentication = requireRecord(authentication, "AUTHENTICATED_IDENTITY_REQUIRED");
  const authoritativeState = requireRecord(authority, "AUTHORITATIVE_STATE_REQUIRED");

  if (!AUTHENTICATION_SOURCES.has(trustedAuthentication.source)) {
    deny("AUTHENTICATION_SOURCE_UNTRUSTED");
  }
  if (!TENANT_ID.test(trustedAuthentication.tenantId ?? "")) {
    deny("AUTHENTICATED_TENANT_REQUIRED");
  }
  if (!SUBJECT_ID.test(trustedAuthentication.subjectId ?? "")) {
    deny("AUTHENTICATED_SUBJECT_REQUIRED");
  }
  if (typeof trustedAuthentication.authenticationId !== "string"
    || trustedAuthentication.authenticationId.length < 1
    || trustedAuthentication.authenticationId.length > 255) {
    deny("AUTHENTICATION_ID_REQUIRED");
  }

  const tenant = requireRecord(authoritativeState.tenant, "TENANT_STATE_REQUIRED");
  const subject = requireRecord(authoritativeState.subject, "SUBJECT_STATE_REQUIRED");
  const membership = requireRecord(authoritativeState.membership, "MEMBERSHIP_STATE_REQUIRED");
  const roles = authoritativeState.roles;

  if (tenant.tenantId !== trustedAuthentication.tenantId
    || subject.subjectId !== trustedAuthentication.subjectId
    || membership.tenantId !== trustedAuthentication.tenantId
    || membership.subjectId !== trustedAuthentication.subjectId) {
    deny("AUTHORITATIVE_STATE_MISMATCH");
  }
  if (tenant.state !== "active") deny("TENANT_INACTIVE");
  if (subject.state !== "active") deny("SUBJECT_INACTIVE");
  if (membership.state !== "active") deny("MEMBERSHIP_INACTIVE");
  if (!isPositiveVersion(tenant.version)
    || !isPositiveVersion(subject.version)
    || !isPositiveVersion(membership.version)) {
    deny("AUTHORITY_VERSION_INVALID");
  }
  if (!Array.isArray(roles) || roles.length === 0 || roles.some((role) => !TENANT_ROLES.has(role))) {
    deny("TENANT_ROLE_REQUIRED");
  }

  const normalizedRoles = Object.freeze([...new Set(roles)].sort());
  const context = Object.freeze({
    tenantId: trustedAuthentication.tenantId,
    subjectId: trustedAuthentication.subjectId,
    roles: normalizedRoles,
    authentication: Object.freeze({
      source: trustedAuthentication.source,
      authenticationId: trustedAuthentication.authenticationId,
    }),
    versions: Object.freeze({
      tenant: tenant.version,
      subject: subject.version,
      membership: membership.version,
    }),
  });
  RESOLVED_CONTEXTS.add(context);
  return context;
}

export function assertNoTenantSwitch(context, claims = []) {
  const trustedContext = requireRecord(context, "TENANT_CONTEXT_REQUIRED");
  if (!RESOLVED_CONTEXTS.has(trustedContext)) deny("TENANT_CONTEXT_INVALID");
  if (!Array.isArray(claims)) deny("TENANT_CLAIMS_INVALID");

  for (const claim of claims) {
    if (!claim || typeof claim !== "object" || Array.isArray(claim)
      || !CLAIM_SOURCES.has(claim.source)
      || !TENANT_ID.test(claim.tenantId ?? "")) {
      deny("TENANT_CLAIM_INVALID");
    }
    if (claim.tenantId !== trustedContext.tenantId) deny("TENANT_CONTEXT_MISMATCH");
  }

  return trustedContext;
}

export function tenantSafeDenial(error) {
  if (!(error instanceof TenantContextError)) throw error;
  return TENANT_CONTEXT_DENIAL;
}
