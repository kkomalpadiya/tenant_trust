import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  POLICY_DECISION_PROVENANCE_POLICY,
  createPolicyDecisionProvenance,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  policy: "pol_018f1234-5678-7abc-8def-0123456789ab",
  request: "req_018f1234-5678-7abc-8def-0123456789ab",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
  decision: "dec_018f1234-5678-7abc-8def-0123456789ab",
});
const hash = "ab".repeat(32);

function evaluation() {
  const input = {
    schemaVersion: "1.0.0",
    contractId: "opa-decision-input-v1",
    identity: { certificateId: ids.certificate, statusVersion: 7 },
    tenantContext: {
      tenantId: ids.tenant,
      subjectId: ids.subject,
      versions: { tenant: 4, subject: 5, membership: 6 },
    },
    action: "record:export",
    resource: {
      resourceType: "tenant-record",
      resourceIdHashSha256: hash,
      sensitivity: "sensitive",
      scope: "tenant",
      ownerSubjectId: null,
    },
    trust: {
      transitionId: ids.transition,
      updateVersion: 12,
      modelVersion: "1.0.0",
      configurationVersion: 3,
      explanationHashSha256: hash,
    },
    requestContext: {
      requestId: ids.request,
      correlationId: ids.correlation,
      requestedAt: "2026-10-20T09:00:00.000Z",
      method: "POST",
      routeTemplate: "/v1/tenant-records/export",
      sourceNetworkZone: "unknown",
      stepUp: {
        status: "valid",
        proofIdHashSha256: "cd".repeat(32),
        tenantId: ids.tenant,
        subjectId: ids.subject,
        action: "record:export",
        sessionIdHashSha256: "ef".repeat(32),
        verifiedAt: "2026-10-20T08:59:30.000Z",
        expiresAt: "2026-10-20T09:04:30.000Z",
      },
    },
  };
  const decision = {
    schemaVersion: "1.0.0",
    contractId: "opa-decision-output-v1",
    decisionId: ids.decision,
    requestId: ids.request,
    correlationId: ids.correlation,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    outcome: "ALLOW",
    reasonCodes: ["POLICY_ALLOW"],
    evaluatedAt: "2026-10-20T09:00:00.050Z",
    input: { contractId: "opa-decision-input-v1", hashSha256: hash },
    policy: {
      policyVersionId: ids.policy,
      bundleVersion: 2,
      bundleHashSha256: hash,
      decisionPath: "tenant_trust/authorization/decision",
    },
    state: {
      certificateStatusVersion: 7,
      tenantVersion: 4,
      subjectVersion: 5,
      membershipVersion: 6,
      trustTransitionId: ids.transition,
      trustUpdateVersion: 12,
      trustConfigurationVersion: 3,
    },
    obligations: { stepUp: null, quarantine: null },
  };
  return {
    input,
    inputHash: hash,
    policyBundle: {
      policyVersionId: ids.policy,
      bundleVersion: 2,
      bundleHashSha256: hash,
      entrypoint: "tenant_trust/authorization/decision",
    },
    decision,
  };
}

test("canonical provenance links request, result, trust/evidence explanation and policy version", () => {
  const provenance = createPolicyDecisionProvenance(evaluation());

  assert.equal(provenance.document.canonicalizationProfile,
    POLICY_DECISION_PROVENANCE_POLICY.canonicalizationProfile);
  assert.equal(provenance.document.request.requestId, ids.request);
  assert.equal(provenance.document.decision.decisionId, ids.decision);
  assert.equal(provenance.document.trustState.transitionId, ids.transition);
  assert.equal(provenance.document.trustState.explanationHashSha256, hash);
  assert.equal(provenance.document.policy.policyVersionId, ids.policy);
  assert.equal(provenance.document.input.hashSha256, hash);
  assert.equal(
    provenance.hashSha256,
    createHash("sha256").update(provenance.canonicalJson, "utf8").digest("hex"),
  );
  assert.equal(Object.isFrozen(provenance.document.request), true);
  assert.equal(provenance.canonicalJson.includes("proofId\""), false);
  assert.equal(provenance.canonicalJson.includes("resourceId\""), false);
});

test("provenance construction rejects a decision detached from its active policy bundle", () => {
  const detached = evaluation();
  detached.policyBundle = { ...detached.policyBundle, bundleVersion: 3 };
  assert.throws(
    () => createPolicyDecisionProvenance(detached),
    /not bound to its evaluated input and policy/u,
  );
});
