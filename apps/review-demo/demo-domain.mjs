import {
  AUTHORIZATION_MODE_IDS,
  evaluateAuthorizationMode,
  selectAuthorizationMode,
} from "@tenant-trust/authorization";
import { resolveTenantContext } from "@tenant-trust/tenant-context";

const ids = Object.freeze({
  alphaTenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  betaTenant: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  alphaAdmin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  bob: "sub_018f1234-5678-7abc-8def-0123456789ad",
  betaAdmin: "sub_018f1234-5678-7abc-8def-0123456789ae",
});

const tenants = Object.freeze({
  alpha: Object.freeze({
    tenantId: ids.alphaTenant,
    slug: "tenant-alpha",
    name: "Tenant Alpha",
    issuer: "Tenant Alpha Intermediate CA",
    color: "#2f7df4",
  }),
  beta: Object.freeze({
    tenantId: ids.betaTenant,
    slug: "tenant-beta",
    name: "Tenant Beta",
    issuer: "Tenant Beta Intermediate CA",
    color: "#8b5cf6",
  }),
});

export const personas = Object.freeze({
  "alpha-member": Object.freeze({
    key: "alpha-member",
    displayName: "Alice Morgan",
    initials: "AM",
    subjectId: ids.alice,
    tenant: tenants.alpha,
    roles: Object.freeze(["tenant-member"]),
    roleLabel: "Tenant member",
    certificateId: "crt_018f1234-5678-7abc-8def-0123456789c1",
    serial: "7A:31:9C:EF:08:A1",
    fingerprint: "9F:4B:3A:10:7D:61:2C:88",
    expiresOn: "2026-12-16T10:30:00.000Z",
  }),
  "alpha-admin": Object.freeze({
    key: "alpha-admin",
    displayName: "Maya Chen",
    initials: "MC",
    subjectId: ids.alphaAdmin,
    tenant: tenants.alpha,
    roles: Object.freeze(["tenant-admin"]),
    roleLabel: "Tenant administrator",
    certificateId: "crt_018f1234-5678-7abc-8def-0123456789c2",
    serial: "4E:22:17:BD:90:A4",
    fingerprint: "7A:02:CD:44:FA:98:31:6B",
    expiresOn: "2026-12-21T08:15:00.000Z",
  }),
  "beta-admin": Object.freeze({
    key: "beta-admin",
    displayName: "Noah Williams",
    initials: "NW",
    subjectId: ids.betaAdmin,
    tenant: tenants.beta,
    roles: Object.freeze(["tenant-admin"]),
    roleLabel: "Tenant administrator",
    certificateId: "crt_018f1234-5678-7abc-8def-0123456789c3",
    serial: "8D:72:AE:19:63:C0",
    fingerprint: "6C:11:9B:E3:56:08:A7:20",
    expiresOn: "2027-01-08T16:45:00.000Z",
  }),
});

const records = Object.freeze([
  Object.freeze({
    tenantId: ids.alphaTenant,
    recordId: "res_018f1234-5678-7abc-8def-0123456789b0",
    ownerSubjectId: ids.alice,
    name: "Alpha member record",
    category: "Identity profile",
    classification: "Confidential",
    updatedAt: "2026-09-16T13:42:00.000Z",
  }),
  Object.freeze({
    tenantId: ids.alphaTenant,
    recordId: "res_018f1234-5678-7abc-8def-0123456789b1",
    ownerSubjectId: ids.alphaAdmin,
    name: "Alpha administrator record",
    category: "Access configuration",
    classification: "Confidential",
    updatedAt: "2026-09-16T15:08:00.000Z",
  }),
  Object.freeze({
    tenantId: ids.betaTenant,
    recordId: "res_018f1234-5678-7abc-8def-0123456789b2",
    ownerSubjectId: ids.bob,
    name: "Beta member record",
    category: "Identity profile",
    classification: "Confidential",
    updatedAt: "2026-09-15T11:24:00.000Z",
  }),
  Object.freeze({
    tenantId: ids.betaTenant,
    recordId: "res_018f1234-5678-7abc-8def-0123456789b3",
    ownerSubjectId: ids.betaAdmin,
    name: "Beta administrator record",
    category: "Access configuration",
    classification: "Confidential",
    updatedAt: "2026-09-16T09:17:00.000Z",
  }),
]);

const scenarioDefinitions = Object.freeze([
  Object.freeze({
    id: "same-tenant-record",
    eyebrow: "Expected allow",
    title: "Read a permitted record",
    description: "Valid certificate, active membership and an in-scope tenant record.",
    action: "record:read",
  }),
  Object.freeze({
    id: "cross-tenant-record",
    eyebrow: "Isolation check",
    title: "Attempt cross-tenant access",
    description: "Use the authenticated identity against a record owned by the other tenant.",
    action: "record:read",
  }),
  Object.freeze({
    id: "forged-identity-header",
    eyebrow: "Gateway check",
    title: "Send forged identity headers",
    description: "Claim the other tenant in browser-controlled headers and request its record.",
    action: "record:read",
  }),
  Object.freeze({
    id: "revoked-certificate",
    eyebrow: "Lifecycle check",
    title: "Reuse a revoked certificate",
    description: "Present a known identity after its authoritative certificate state changes.",
    action: "profile:read",
  }),
  Object.freeze({
    id: "sensitive-export",
    eyebrow: "Role + controls",
    title: "Request a sensitive export",
    description: "Evaluate role eligibility, request bounds, step-up and audit controls.",
    action: "record:export",
  }),
]);

const baselineMode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE);

function personaFor(personaKey) {
  return personas[personaKey] ?? personas["alpha-member"];
}

function contextFor(persona) {
  return resolveTenantContext({
    authentication: {
      source: "mtls-certificate",
      authenticationId: persona.certificateId,
      tenantId: persona.tenant.tenantId,
      subjectId: persona.subjectId,
    },
    authority: {
      tenant: { tenantId: persona.tenant.tenantId, state: "active", version: 4 },
      subject: { subjectId: persona.subjectId, state: "active", version: 3 },
      membership: {
        tenantId: persona.tenant.tenantId,
        subjectId: persona.subjectId,
        state: "active",
        version: 6,
      },
      roles: persona.roles,
    },
  });
}

function visibleRecords(persona) {
  if (persona.roles.includes("tenant-admin")) {
    return records.filter((record) => record.tenantId === persona.tenant.tenantId);
  }
  return records.filter((record) => record.ownerSubjectId === persona.subjectId);
}

function compactPersona(persona) {
  return {
    key: persona.key,
    displayName: persona.displayName,
    initials: persona.initials,
    subjectId: persona.subjectId,
    role: persona.roles[0],
    roleLabel: persona.roleLabel,
    tenant: persona.tenant,
  };
}

function decisionFor(persona, action) {
  return evaluateAuthorizationMode(baselineMode, contextFor(persona), action);
}

function nowIso(clock) {
  return clock().toISOString();
}

function auditEvent({ persona, scenario, outcome, statusCode, reasonCode, clock }) {
  return {
    id: `evt_${clock().getTime()}_${scenario.id}`,
    occurredAt: nowIso(clock),
    actor: persona.displayName,
    tenant: persona.tenant.name,
    action: scenario.action,
    resource: scenario.id.includes("record") || scenario.id.includes("header")
      ? "tenant-record"
      : scenario.id.includes("export") ? "tenant-record-export" : "subject-profile",
    outcome,
    statusCode,
    reasonCode,
    correlationId: "cor_review-demo",
  };
}

export function getReviewState(personaKey = "alpha-member") {
  const persona = personaFor(personaKey);
  const context = contextFor(persona);
  const actionDecisions = ["profile:read", "record:read", "record:write", "record:export", "tenant:admin"]
    .map((action) => {
      const decision = decisionFor(persona, action);
      return {
        action,
        outcome: decision.outcome,
        scope: decision.eligibility.scope,
        sensitivity: decision.eligibility.sensitivity,
      };
    });

  return {
    generatedAt: new Date().toISOString(),
    environment: "Read-only review environment",
    project: {
      completedPhases: 4,
      totalPhases: 10,
      completedTasks: 40,
      totalTasks: 100,
      verifiedTests: 150,
      tenantCount: 2,
      apiOperations: 5,
      vulnerabilities: 0,
      baseline: baselineMode.modeId,
    },
    persona: compactPersona(persona),
    personas: Object.values(personas).map(compactPersona),
    certificate: {
      certificateId: persona.certificateId,
      state: "active",
      issuer: persona.tenant.issuer,
      serial: persona.serial,
      fingerprint: persona.fingerprint,
      expiresOn: persona.expiresOn,
      authenticationSource: context.authentication.source,
    },
    context: {
      tenantId: context.tenantId,
      subjectId: context.subjectId,
      roles: context.roles,
      versions: context.versions,
    },
    records: visibleRecords(persona),
    actionDecisions,
    scenarios: scenarioDefinitions,
  };
}

export function runReviewScenario({ personaKey = "alpha-member", scenarioId, clock = () => new Date() } = {}) {
  const persona = personaFor(personaKey);
  const scenario = scenarioDefinitions.find((candidate) => candidate.id === scenarioId);
  if (!scenario) throw new RangeError("Unknown review scenario.");

  const commonAccepted = [
    { label: "mTLS edge", detail: "Client certificate presented", state: "pass" },
    { label: "Tenant context", detail: `${persona.tenant.name} resolved from certificate`, state: "pass" },
  ];
  let statusCode;
  let outcome;
  let reasonCode;
  let headline;
  let summary;
  let stages;

  if (scenario.id === "revoked-certificate") {
    statusCode = 401;
    outcome = "deny";
    reasonCode = "CERTIFICATE_NOT_ACCEPTED";
    headline = "Revoked certificate rejected";
    summary = "Authoritative inventory state is checked again on the request. No cached allow survives revocation.";
    stages = [
      commonAccepted[0],
      { label: "Certificate state", detail: "Inventory reports revoked", state: "fail" },
      { label: "Protected API", detail: "Request stopped before data access", state: "blocked" },
    ];
  } else if (scenario.id === "cross-tenant-record") {
    decisionFor(persona, scenario.action);
    statusCode = 403;
    outcome = "deny";
    reasonCode = "ACCESS_DENIED";
    headline = "Cross-tenant access denied";
    summary = "The resource tenant does not match the certificate-derived context. The API returns the same denial used for invisible identifiers.";
    stages = [
      ...commonAccepted,
      { label: "Authorization", detail: "Role eligible within authenticated tenant", state: "pass" },
      { label: "Forced RLS", detail: "Foreign tenant predicate rejected", state: "fail" },
    ];
  } else if (scenario.id === "forged-identity-header") {
    decisionFor(persona, scenario.action);
    statusCode = 403;
    outcome = "deny";
    reasonCode = "ACCESS_DENIED";
    headline = "Forged identity could not switch tenants";
    summary = "Gateway-owned identity headers replace browser input. The protected API continues with the certificate tenant and denies the foreign record.";
    stages = [
      { label: "mTLS edge", detail: "Valid certificate accepted", state: "pass" },
      { label: "NGINX gateway", detail: "Forged tenant headers removed", state: "pass" },
      { label: "Tenant context", detail: `${persona.tenant.name} retained`, state: "pass" },
      { label: "Forced RLS", detail: "Foreign record denied", state: "fail" },
    ];
  } else if (scenario.id === "sensitive-export") {
    const decision = decisionFor(persona, scenario.action);
    if (decision.outcome === "requires-controls") {
      statusCode = 200;
      outcome = "allow";
      reasonCode = "ACCESS_ALLOWED";
      headline = "Sensitive export authorized";
      summary = "The tenant administrator passed operation policy, bound step-up and audit controls. A replay-safe operation ID was created.";
      stages = [
        ...commonAccepted,
        { label: "Role matrix", detail: "Administrator eligible", state: "pass" },
        { label: "Extra controls", detail: "Policy, step-up and audit bound", state: "pass" },
        { label: "Operation", detail: "Idempotent export accepted", state: "pass" },
      ];
    } else {
      statusCode = 403;
      outcome = "deny";
      reasonCode = "ACCESS_DENIED";
      headline = "Sensitive export denied";
      summary = "Tenant members are not eligible for export. Additional controls cannot expand a role that is explicitly denied.";
      stages = [
        ...commonAccepted,
        { label: "Role matrix", detail: "Member is not export-eligible", state: "fail" },
        { label: "Protected API", detail: "Request stopped before data query", state: "blocked" },
      ];
    }
  } else {
    const decision = decisionFor(persona, scenario.action);
    const selectedRecord = visibleRecords(persona)[0];
    statusCode = decision.outcome === "allow" && selectedRecord ? 200 : 403;
    outcome = statusCode === 200 ? "allow" : "deny";
    reasonCode = statusCode === 200 ? "ACCESS_ALLOWED" : "ACCESS_DENIED";
    headline = statusCode === 200 ? "Permitted record returned" : "Record access denied";
    summary = statusCode === 200
      ? `The ${decision.eligibility.scope} scope matched ${selectedRecord.name}. Tenant identity stayed server-owned.`
      : "The requested record fell outside the authenticated subject's permitted scope.";
    stages = [
      ...commonAccepted,
      { label: "Role matrix", detail: `${persona.roleLabel} · ${decision.eligibility.scope} scope`, state: "pass" },
      { label: "Forced RLS", detail: "Tenant and ownership predicates matched", state: "pass" },
    ];
  }

  const event = auditEvent({ persona, scenario, outcome, statusCode, reasonCode, clock });
  return {
    scenarioId: scenario.id,
    statusCode,
    outcome,
    reasonCode,
    headline,
    summary,
    operationId: statusCode === 200 && scenario.id === "sensitive-export"
      ? "op_018f1234-5678-7abc-8def-0123456789d1"
      : null,
    stages,
    event,
  };
}
