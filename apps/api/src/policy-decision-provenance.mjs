import { createHash } from "node:crypto";

const EVALUATION_KEYS = Object.freeze(["decision", "input", "inputHash", "policyBundle"]);

export const POLICY_DECISION_PROVENANCE_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  mechanism: "append-only-policy-decision-provenance-v1",
  canonicalizationProfile: "tenant-trust-authorization-decision-provenance-json-v1",
  digestAlgorithm: "sha256",
  failClosedOnCaptureFailure: true,
  rawResourceIdentifiersCaptured: false,
  rawRequestPayloadCaptured: false,
});

function exactRecord(value, fields, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(message);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(message);
  }
  return value;
}

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Policy decision provenance contains a non-canonical value.");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function assertBindings(evaluation) {
  const { decision, input, inputHash, policyBundle } = evaluation;
  if (decision.requestId !== input.requestContext.requestId
    || decision.decisionId?.slice(4) !== input.requestContext.requestId?.slice(4)
    || decision.correlationId !== input.requestContext.correlationId
    || decision.tenantId !== input.tenantContext.tenantId
    || decision.subjectId !== input.tenantContext.subjectId
    || decision.input.contractId !== input.contractId
    || decision.input.hashSha256 !== inputHash
    || decision.policy.policyVersionId !== policyBundle.policyVersionId
    || decision.policy.bundleVersion !== policyBundle.bundleVersion
    || decision.policy.bundleHashSha256 !== policyBundle.bundleHashSha256
    || decision.policy.decisionPath !== policyBundle.entrypoint
    || decision.state.certificateStatusVersion !== input.identity.statusVersion
    || decision.state.tenantVersion !== input.tenantContext.versions.tenant
    || decision.state.subjectVersion !== input.tenantContext.versions.subject
    || decision.state.membershipVersion !== input.tenantContext.versions.membership
    || decision.state.trustTransitionId !== input.trust.transitionId
    || decision.state.trustUpdateVersion !== input.trust.updateVersion
    || decision.state.trustConfigurationVersion !== input.trust.configurationVersion) {
    throw new TypeError("Policy decision provenance is not bound to its evaluated input and policy.");
  }
}

export function createPolicyDecisionProvenance(evaluation) {
  exactRecord(evaluation, EVALUATION_KEYS, "A complete policy evaluation is required for provenance.");
  const { decision, input } = evaluation;
  if (!decision || !input || !evaluation.policyBundle || typeof evaluation.inputHash !== "string") {
    throw new TypeError("A complete policy evaluation is required for provenance.");
  }
  assertBindings(evaluation);

  const document = {
    schemaVersion: POLICY_DECISION_PROVENANCE_POLICY.schemaVersion,
    provenanceType: "authorization-decision",
    canonicalizationProfile: POLICY_DECISION_PROVENANCE_POLICY.canonicalizationProfile,
    decision: {
      contractId: decision.contractId,
      decisionId: decision.decisionId,
      outcome: decision.outcome,
      reasonCodes: [...decision.reasonCodes],
      obligations: structuredClone(decision.obligations),
      evaluatedAt: decision.evaluatedAt,
    },
    request: {
      requestId: input.requestContext.requestId,
      correlationId: input.requestContext.correlationId,
      requestedAt: input.requestContext.requestedAt,
      method: input.requestContext.method,
      routeTemplate: input.requestContext.routeTemplate,
      sourceNetworkZone: input.requestContext.sourceNetworkZone,
      tenantId: input.tenantContext.tenantId,
      subjectId: input.tenantContext.subjectId,
      action: input.action,
      resource: {
        resourceType: input.resource.resourceType,
        resourceIdHashSha256: input.resource.resourceIdHashSha256,
        sensitivity: input.resource.sensitivity,
        scope: input.resource.scope,
        ownerSubjectId: input.resource.ownerSubjectId,
      },
      stepUp: structuredClone(input.requestContext.stepUp),
    },
    identityState: {
      certificateId: input.identity.certificateId,
      certificateStatusVersion: input.identity.statusVersion,
      tenantVersion: input.tenantContext.versions.tenant,
      subjectVersion: input.tenantContext.versions.subject,
      membershipVersion: input.tenantContext.versions.membership,
    },
    trustState: {
      transitionId: input.trust.transitionId,
      updateVersion: input.trust.updateVersion,
      modelVersion: input.trust.modelVersion,
      configurationVersion: input.trust.configurationVersion,
      explanationHashSha256: input.trust.explanationHashSha256,
    },
    policy: {
      policyVersionId: decision.policy.policyVersionId,
      bundleVersion: decision.policy.bundleVersion,
      bundleHashSha256: decision.policy.bundleHashSha256,
      decisionPath: decision.policy.decisionPath,
    },
    input: {
      contractId: decision.input.contractId,
      hashSha256: evaluation.inputHash,
    },
  };
  const canonicalJson = canonicalize(document);
  const hashSha256 = createHash("sha256").update(canonicalJson, "utf8").digest("hex");
  return deepFreeze({ document, canonicalJson, hashSha256 });
}
