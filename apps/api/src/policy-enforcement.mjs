import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import commonSchema from "@tenant-trust/contracts/schemas/common.schema.json" with { type: "json" };
import inputSchema from "@tenant-trust/contracts/schemas/policy/opa-decision-input.schema.json" with { type: "json" };
import outputSchema from "@tenant-trust/contracts/schemas/policy/opa-decision-output.schema.json" with { type: "json" };

const DECISION_PATH = "/v1/data/tenant_trust/authorization/decision";
const POLICY_SERVICES = new WeakSet();
const DECISION_CLIENTS = new WeakSet();

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(commonSchema);
const validateInput = ajv.compile(inputSchema);
const validateOutput = ajv.compile(outputSchema);

export const POLICY_ENFORCEMENT_POLICY = Object.freeze({
  id: "adaptive-trust-opa-enforcement-v1",
  authorizationModeId: "adaptive-trust-opa-v1",
  inputContractId: "opa-decision-input-v1",
  outputContractId: "opa-decision-output-v1",
  decisionPath: "tenant_trust/authorization/decision",
  inputCanonicalization: "tenant-trust-policy-json-v1",
  onlyAllowingOutcome: "ALLOW",
  failClosed: true,
});

export class PolicyDecisionUnavailableError extends Error {
  constructor(reasonCode = "POLICY_DECISION_UNAVAILABLE") {
    super("Policy decision unavailable.");
    this.name = "PolicyDecisionUnavailableError";
    this.reasonCode = reasonCode;
  }
}

function unavailable(reasonCode) {
  throw new PolicyDecisionUnavailableError(reasonCode);
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) unavailable("POLICY_INPUT_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  unavailable("POLICY_INPUT_INVALID");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function exactUtc(value, reasonCode) {
  if (typeof value !== "string" || !value.endsWith("Z")) unavailable(reasonCode);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) unavailable(reasonCode);
  return value;
}

function requireRecord(value, reasonCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) unavailable(reasonCode);
  return value;
}

function absentStepUp() {
  return Object.freeze({
    status: "absent",
    proofIdHashSha256: null,
    tenantId: null,
    subjectId: null,
    action: null,
    sessionIdHashSha256: null,
    verifiedAt: null,
    expiresAt: null,
  });
}

function validateWith(validator, value, reasonCode) {
  if (!validator(value)) unavailable(reasonCode);
  return value;
}

function buildDecisionUrl(baseUrl) {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    unavailable("POLICY_ENDPOINT_INVALID");
  }
  if (!new Set(["http:", "https:"]).has(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash) {
    unavailable("POLICY_ENDPOINT_INVALID");
  }
  return new URL(DECISION_PATH, parsed).toString();
}

export function hashPolicyInput(input) {
  validateWith(validateInput, input, "POLICY_INPUT_INVALID");
  return createHash("sha256").update(canonicalize(input), "utf8").digest("hex");
}

export function createOpaPolicyDecisionClient({ baseUrl, fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("A fetch implementation is required.");
  const decisionUrl = buildDecisionUrl(baseUrl);
  const client = Object.freeze({
    async decide(input, { signal } = {}) {
      validateWith(validateInput, input, "POLICY_INPUT_INVALID");
      let response;
      try {
        response = await fetchImpl(decisionUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ input }),
          signal,
        });
      } catch {
        unavailable("POLICY_REQUEST_FAILED");
      }
      if (!response || response.ok !== true || typeof response.json !== "function") {
        unavailable("POLICY_RESPONSE_UNAVAILABLE");
      }
      let body;
      try {
        body = await response.json();
      } catch {
        unavailable("POLICY_RESPONSE_INVALID");
      }
      if (!body || typeof body !== "object" || Array.isArray(body)
        || Object.keys(body).length !== 1
        || !("result" in body)) {
        unavailable("POLICY_RESPONSE_INVALID");
      }
      validateWith(validateOutput, body.result, "POLICY_RESPONSE_INVALID");
      return deepFreeze(structuredClone(body.result));
    },
  });
  DECISION_CLIENTS.add(client);
  return client;
}

export function assertOpaPolicyDecisionClient(value) {
  if (!value || typeof value !== "object" || !DECISION_CLIENTS.has(value)) {
    throw new TypeError("A branded OPA policy decision client is required.");
  }
  return value;
}

function assertDecisionBinding(decision, input, inputHash) {
  const expected = [
    [decision.requestId, input.requestContext.requestId],
    [decision.correlationId, input.requestContext.correlationId],
    [decision.tenantId, input.tenantContext.tenantId],
    [decision.subjectId, input.tenantContext.subjectId],
    [decision.input.contractId, input.contractId],
    [decision.input.hashSha256, inputHash],
    [decision.state.certificateStatusVersion, input.identity.statusVersion],
    [decision.state.tenantVersion, input.tenantContext.versions.tenant],
    [decision.state.subjectVersion, input.tenantContext.versions.subject],
    [decision.state.membershipVersion, input.tenantContext.versions.membership],
    [decision.state.trustTransitionId, input.trust.transitionId],
    [decision.state.trustUpdateVersion, input.trust.updateVersion],
    [decision.state.trustConfigurationVersion, input.trust.configurationVersion],
  ];
  if (expected.some(([actual, wanted]) => actual !== wanted)) {
    unavailable("POLICY_RESPONSE_BINDING_MISMATCH");
  }
  exactUtc(decision.evaluatedAt, "POLICY_RESPONSE_INVALID");
  if (Date.parse(decision.evaluatedAt) < Date.parse(input.requestContext.requestedAt)) {
    unavailable("POLICY_RESPONSE_TIME_INVALID");
  }
}

export function createPolicyEnforcementService({ trustScoreLookupService, decisionClient } = {}) {
  if (!trustScoreLookupService || typeof trustScoreLookupService.lookup !== "function") {
    throw new TypeError("A trust-score lookup service is required.");
  }
  assertOpaPolicyDecisionClient(decisionClient);

  const service = Object.freeze({
    policy: POLICY_ENFORCEMENT_POLICY,

    async decide({ authentication, context, requestState, authorization, action, policyRequest, signal } = {}) {
      requireRecord(authentication, "POLICY_INPUT_INVALID");
      requireRecord(context, "POLICY_INPUT_INVALID");
      requireRecord(requestState, "POLICY_INPUT_INVALID");
      requireRecord(authorization, "POLICY_INPUT_INVALID");
      const request = requireRecord(policyRequest, "POLICY_INPUT_INVALID");
      if (authorization.modeId !== POLICY_ENFORCEMENT_POLICY.authorizationModeId
        || authorization.outcome !== "policy-required"
        || authorization.eligibility?.action !== action) {
        unavailable("POLICY_AUTHORIZATION_CONTEXT_INVALID");
      }

      let trust;
      try {
        trust = await trustScoreLookupService.lookup({ context, signal });
      } catch {
        unavailable("TRUST_LOOKUP_UNAVAILABLE");
      }
      requireRecord(trust, "TRUST_STATE_INVALID");
      if (trust.tenantId !== context.tenantId || trust.subjectId !== context.subjectId) {
        unavailable("TRUST_STATE_BINDING_MISMATCH");
      }

      const input = {
        schemaVersion: "1.0.0",
        contractId: POLICY_ENFORCEMENT_POLICY.inputContractId,
        identity: {
          source: "mtls-certificate",
          authenticationId: authentication.authenticationId,
          tenantId: context.tenantId,
          subjectId: context.subjectId,
          certificateId: requestState.certificateId,
          issuerId: authentication.certificate?.issuerId,
          serialNumber: authentication.certificate?.serialNumber,
          fingerprintSha256: authentication.certificate?.fingerprintSha256,
          valid: true,
          certificateState: "active",
          statusSource: "authoritative",
          statusVersion: requestState.certificateStatusVersion,
          statusObservedAt: requestState.observedAt,
          checkedAt: requestState.checkedAt,
          validUntil: requestState.validUntil,
        },
        tenantContext: {
          tenantId: context.tenantId,
          subjectId: context.subjectId,
          roles: [...context.roles],
          tenantState: "active",
          subjectState: "active",
          membershipState: "active",
          versions: { ...context.versions },
        },
        action,
        resource: {
          tenantId: context.tenantId,
          resourceType: authorization.eligibility.resourceType,
          resourceIdHashSha256: request.resourceIdHashSha256,
          sensitivity: authorization.eligibility.sensitivity,
          scope: authorization.eligibility.scope,
          ownerSubjectId: request.ownerSubjectId ?? null,
        },
        trust: structuredClone(trust),
        requestContext: {
          requestId: request.requestId,
          correlationId: request.correlationId,
          requestedAt: exactUtc(request.requestedAt, "POLICY_INPUT_INVALID"),
          method: request.method,
          routeTemplate: request.routeTemplate,
          sourceNetworkZone: request.sourceNetworkZone,
          stepUp: request.stepUp ? structuredClone(request.stepUp) : absentStepUp(),
        },
      };
      validateWith(validateInput, input, "POLICY_INPUT_INVALID");
      const immutableInput = deepFreeze(structuredClone(input));
      const inputHash = hashPolicyInput(immutableInput);
      const decision = await decisionClient.decide(immutableInput, { signal });
      assertDecisionBinding(decision, immutableInput, inputHash);
      if (immutableInput.trust.requiredOutcome !== null
        && decision.outcome !== immutableInput.trust.requiredOutcome) {
        unavailable("POLICY_RESPONSE_CONSTRAINT_MISMATCH");
      }
      return Object.freeze({ input: immutableInput, inputHash, decision });
    },
  });
  POLICY_SERVICES.add(service);
  return service;
}

export function assertPolicyEnforcementService(value) {
  if (!value || typeof value !== "object" || !POLICY_SERVICES.has(value)
    || value.policy !== POLICY_ENFORCEMENT_POLICY) {
    throw new TypeError("A branded policy enforcement service is required.");
  }
  return value;
}
