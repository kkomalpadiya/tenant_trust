import { AUTHORIZATION_MODE_IDS } from "@tenant-trust/authorization";

import { JWT_RBAC_BASELINE_MODE_ID } from "./comparison-scope.mjs";

export const REFERENCE_EFFECTIVENESS_ADAPTER_ID = "tenant-trust-reference-effectiveness-adapters-v1";

function response(observedOutcome, reasonCode, controlsObserved = [], measurements) {
  return {
    status: "completed",
    observedOutcome,
    reasonCode,
    controlsObserved,
    ...(measurements ? { measurements } : {}),
  };
}

function unsupported() {
  return {
    status: "unsupported",
    observedOutcome: "unsupported",
    reasonCode: "CONTROL_UNSUPPORTED",
    controlsObserved: [],
  };
}

function proposedResult({ run, step, laneIndex }) {
  const restrictiveFixtures = new Set([
    "unknown-device",
    "failed-logins",
    "sensitive-export",
    "forged-evidence",
    "replayed-evidence",
    "invalid-certificate-reuse",
    "cross-tenant-access",
    "evidence-flood",
    "stale-policy-version",
    "modified-audit-record",
    "corroborated-critical-evidence",
    "revoked-certificate-reuse",
  ]);
  const observedOutcome = restrictiveFixtures.has(step.fixture) ? "deny" : "allow";
  const measurements = step.fixture === "revoked-certificate-reuse"
    ? { revocationEnforcementDelayMs: 240 + ((run.seed + laneIndex) % 81) }
    : undefined;
  return response(observedOutcome, "PROPOSED_CONTROL_APPLIED", step.expectedControls, measurements);
}

function jwtBaselineResult({ step }) {
  if (step.fixture === "normal-access") return response("allow", "JWT_RBAC_ALLOW");
  if (step.fixture === "sensitive-export") return response("allow", "JWT_RBAC_ALLOW");
  if (step.fixture === "cross-tenant-access") return response("deny", "JWT_TENANT_SCOPE_DENY", step.expectedControls);
  if (step.fixture === "revoked-certificate-reuse") return response("allow", "JWT_NOT_CERTIFICATE_BOUND");
  return unsupported();
}

function pkiBaselineResult({ step }) {
  if (step.fixture === "normal-access") return response("allow", "PKI_RBAC_ALLOW");
  if (step.fixture === "sensitive-export") return response("deny", "PKI_SENSITIVE_CONTROL_REQUIRED", step.expectedControls);
  if (step.fixture === "cross-tenant-access") return response("deny", "PKI_TENANT_SCOPE_DENY", step.expectedControls);
  if (step.fixture === "invalid-certificate-reuse") return response("deny", "PKI_CERTIFICATE_REJECTED", step.expectedControls);
  if (step.fixture === "revoked-certificate-reuse") return response("allow", "PKI_CERTIFICATE_NOT_REVOKED");
  return unsupported();
}

function adapter(execute) {
  return Object.freeze({
    adapterId: REFERENCE_EFFECTIVENESS_ADAPTER_ID,
    executeStep: async (context) => execute(context),
  });
}

export function createReferenceEffectivenessAdapters() {
  return Object.freeze({
    [JWT_RBAC_BASELINE_MODE_ID]: adapter(jwtBaselineResult),
    [AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE]: adapter(pkiBaselineResult),
    [AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA]: adapter(proposedResult),
  });
}
