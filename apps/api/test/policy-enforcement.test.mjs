import assert from "node:assert/strict";
import test from "node:test";
import {
  AUTHORIZATION_MODE_IDS,
  evaluateAuthorizationMode,
  selectAuthorizationMode,
} from "@tenant-trust/authorization";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import {
  PolicyDecisionUnavailableError,
  createOpaPolicyDecisionClient,
  createPolicyEnforcementService,
  hashPolicyInput,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  policy: "pol_018f1234-5678-7abc-8def-0123456789ab",
  request: "req_018f1234-5678-7abc-8def-0123456789ab",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
  decision: "dec_018f1234-5678-7abc-8def-0123456789ab",
});
const hash = "ab".repeat(32);
const mode = selectAuthorizationMode(AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA);
const authentication = Object.freeze({
  source: "mtls-certificate",
  authenticationId: `sha256:${hash}`,
  tenantId: ids.tenant,
  subjectId: ids.subject,
  certificate: Object.freeze({
    issuerId: ids.issuer,
    serialNumber: "01AF".padEnd(32, "0"),
    fingerprintSha256: hash,
  }),
});
const context = resolveTenantContext({
  authentication,
  authority: {
    tenant: { tenantId: ids.tenant, state: "active", version: 4 },
    subject: { subjectId: ids.subject, state: "active", version: 5 },
    membership: { tenantId: ids.tenant, subjectId: ids.subject, state: "active", version: 6 },
    roles: ["tenant-admin"],
  },
});

function freshTrust() {
  return {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    state: "fresh",
    usableForPolicy: true,
    requiredOutcome: null,
    reasonCode: null,
    policyScore: 99,
    policyBand: "high",
    lastKnownScore: 99,
    lastKnownBand: "high",
    ageSeconds: 1,
    staleAfterSeconds: 300,
    transitionId: ids.transition,
    updateVersion: 12,
    modelVersion: "1.0.0",
    configurationVersion: 3,
    observedAt: "2026-10-13T08:59:30.000Z",
    evaluatedAt: "2026-10-13T08:59:31.000Z",
    recordedAt: "2026-10-13T08:59:31.100Z",
    explanationHashSha256: hash,
  };
}

function requestState() {
  return {
    certificateId: ids.certificate,
    certificateStatusVersion: 7,
    observedAt: "2026-10-13T08:59:59.000Z",
    checkedAt: "2026-10-13T09:00:00.000Z",
    validUntil: "2026-10-13T09:00:05.000Z",
  };
}

function policyRequest() {
  return {
    requestId: ids.request,
    correlationId: ids.correlation,
    requestedAt: "2026-10-13T09:00:00.000Z",
    method: "POST",
    routeTemplate: "/v1/tenant-records/export",
    sourceNetworkZone: "unknown",
    resourceIdHashSha256: hash,
    ownerSubjectId: null,
  };
}

function outputFor(input, outcome = "ALLOW", overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    contractId: "opa-decision-output-v1",
    decisionId: ids.decision,
    requestId: input.requestContext.requestId,
    correlationId: input.requestContext.correlationId,
    tenantId: input.tenantContext.tenantId,
    subjectId: input.tenantContext.subjectId,
    outcome,
    reasonCodes: [outcome === "ALLOW" ? "ACCESS_ALLOWED" : "ACCESS_DENIED"],
    evaluatedAt: "2026-10-13T09:00:00.050Z",
    input: { contractId: input.contractId, hashSha256: hashPolicyInput(input) },
    policy: {
      policyVersionId: ids.policy,
      bundleVersion: 2,
      bundleHashSha256: hash,
      decisionPath: "tenant_trust/authorization/decision",
    },
    state: {
      certificateStatusVersion: input.identity.statusVersion,
      tenantVersion: input.tenantContext.versions.tenant,
      subjectVersion: input.tenantContext.versions.subject,
      membershipVersion: input.tenantContext.versions.membership,
      trustTransitionId: input.trust.transitionId,
      trustUpdateVersion: input.trust.updateVersion,
      trustConfigurationVersion: input.trust.configurationVersion,
    },
    obligations: { stepUp: null, quarantine: null },
    ...overrides,
  };
}

function enforcementWith(fetchImpl, trust = freshTrust()) {
  const decisionClient = createOpaPolicyDecisionClient({
    baseUrl: "http://opa.internal:8181/ignored",
    fetchImpl,
  });
  return createPolicyEnforcementService({
    trustScoreLookupService: { lookup: async () => structuredClone(trust) },
    decisionClient,
  });
}

async function decideWith(service) {
  const authorization = evaluateAuthorizationMode(mode, context, "record:export");
  return service.decide({
    authentication,
    context,
    requestState: requestState(),
    authorization,
    action: "record:export",
    policyRequest: policyRequest(),
  });
}

test("posts one complete contract-bound decision request to the exact OPA path", async () => {
  let observed;
  const service = enforcementWith(async (url, options) => {
    observed = { url, options };
    const { input } = JSON.parse(options.body);
    return { ok: true, json: async () => ({ result: outputFor(input) }) };
  });

  const evaluation = await decideWith(service);

  assert.equal(observed.url, "http://opa.internal:8181/v1/data/tenant_trust/authorization/decision");
  assert.equal(observed.options.method, "POST");
  assert.equal(observed.options.headers["content-type"], "application/json");
  assert.equal(evaluation.decision.outcome, "ALLOW");
  assert.equal(evaluation.input.identity.valid, true);
  assert.equal(evaluation.input.tenantContext.roles[0], "tenant-admin");
  assert.equal(evaluation.input.trust.policyScore, 99);
  assert.equal(evaluation.input.resource.sensitivity, "sensitive");
  assert.equal(evaluation.input.requestContext.routeTemplate, "/v1/tenant-records/export");
  assert.ok(Object.isFrozen(evaluation.input));
});

test("fails closed for network, malformed, and state-binding failures", async () => {
  const failures = [
    async () => { throw new Error("network detail must not escape"); },
    async () => ({ ok: true, json: async () => ({}) }),
    async (_url, options) => {
      const { input } = JSON.parse(options.body);
      return {
        ok: true,
        json: async () => ({ result: outputFor(input, "ALLOW", { tenantId: ids.subject }) }),
      };
    },
  ];

  for (const fetchImpl of failures) {
    await assert.rejects(decideWith(enforcementWith(fetchImpl)), PolicyDecisionUnavailableError);
  }
});

test("stale trust is a mandatory DENY signal that an OPA ALLOW cannot override", async () => {
  const stale = {
    ...freshTrust(),
    state: "stale",
    usableForPolicy: false,
    requiredOutcome: "DENY",
    reasonCode: "TRUST_STATE_STALE",
    policyScore: null,
    policyBand: null,
  };
  const service = enforcementWith(async (_url, options) => {
    const { input } = JSON.parse(options.body);
    assert.equal(input.trust.requiredOutcome, "DENY");
    assert.equal(input.trust.lastKnownScore, 99);
    return { ok: true, json: async () => ({ result: outputFor(input, "ALLOW") }) };
  }, stale);

  await assert.rejects(decideWith(service), (error) => {
    assert.ok(error instanceof PolicyDecisionUnavailableError);
    assert.equal(error.reasonCode, "POLICY_RESPONSE_CONSTRAINT_MISMATCH");
    return true;
  });
});

test("trust state for another tenant is rejected before OPA", async () => {
  let called = false;
  const foreignTrust = {
    ...freshTrust(),
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  };
  const service = enforcementWith(async () => {
    called = true;
    throw new Error("must not call OPA");
  }, foreignTrust);

  await assert.rejects(decideWith(service), (error) => {
    assert.ok(error instanceof PolicyDecisionUnavailableError);
    assert.equal(error.reasonCode, "TRUST_STATE_BINDING_MISMATCH");
    return true;
  });
  assert.equal(called, false);
});
