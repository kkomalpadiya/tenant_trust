import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaRoot = fileURLToPath(new URL("../schemas/", import.meta.url));
const common = JSON.parse(readFileSync(`${schemaRoot}/common.schema.json`, "utf8"));
const inputSchema = JSON.parse(readFileSync(`${schemaRoot}/policy/opa-decision-input.schema.json`, "utf8"));
const outputSchema = JSON.parse(readFileSync(`${schemaRoot}/policy/opa-decision-output.schema.json`, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateInput = ajv.compile(inputSchema);
const validateOutput = ajv.compile(outputSchema);

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  otherTenant: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  policy: "pol_018f1234-5678-7abc-8def-0123456789ab",
  request: "req_018f1234-5678-7abc-8def-0123456789ab",
  decision: "dec_018f1234-5678-7abc-8def-0123456789ab",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
});
const hash = "ab".repeat(32);

function absentStepUp() {
  return {
    status: "absent",
    proofIdHashSha256: null,
    tenantId: null,
    subjectId: null,
    action: null,
    sessionIdHashSha256: null,
    verifiedAt: null,
    expiresAt: null,
  };
}

function freshTrust() {
  return {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    state: "fresh",
    usableForPolicy: true,
    requiredOutcome: null,
    reasonCode: null,
    policyScore: 72.5,
    policyBand: "high",
    lastKnownScore: 72.5,
    lastKnownBand: "high",
    ageSeconds: 4.25,
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

function decisionInput() {
  return {
    schemaVersion: "1.0.0",
    contractId: "opa-decision-input-v1",
    identity: {
      source: "mtls-certificate",
      authenticationId: `sha256:${hash}`,
      tenantId: ids.tenant,
      subjectId: ids.subject,
      certificateId: ids.certificate,
      issuerId: ids.issuer,
      serialNumber: "01AF".padEnd(32, "0"),
      fingerprintSha256: hash,
      valid: true,
      certificateState: "active",
      statusSource: "authoritative",
      statusVersion: 7,
      statusObservedAt: "2026-10-13T08:59:59.000Z",
      checkedAt: "2026-10-13T09:00:00.000Z",
      validUntil: "2026-10-13T09:00:05.000Z",
    },
    tenantContext: {
      tenantId: ids.tenant,
      subjectId: ids.subject,
      roles: ["tenant-admin"],
      tenantState: "active",
      subjectState: "active",
      membershipState: "active",
      versions: { tenant: 4, subject: 5, membership: 6 },
    },
    action: "record:export",
    resource: {
      tenantId: ids.tenant,
      resourceType: "tenant-record-export",
      resourceIdHashSha256: hash,
      sensitivity: "sensitive",
      scope: "tenant",
      ownerSubjectId: null,
    },
    trust: freshTrust(),
    requestContext: {
      requestId: ids.request,
      correlationId: ids.correlation,
      requestedAt: "2026-10-13T09:00:00.000Z",
      method: "POST",
      routeTemplate: "/v1/records/export",
      sourceNetworkZone: "external",
      stepUp: absentStepUp(),
    },
  };
}

function decisionOutput(outcome) {
  const obligations = {
    stepUp: outcome === "STEP_UP"
      ? { required: true, binding: ["tenant", "subject", "action", "session"], maximumAgeSeconds: 300 }
      : null,
    quarantine: outcome === "QUARANTINE"
      ? { required: true, actionType: "restrict-access" }
      : null,
  };
  return {
    schemaVersion: "1.0.0",
    contractId: "opa-decision-output-v1",
    decisionId: ids.decision,
    requestId: ids.request,
    correlationId: ids.correlation,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    outcome,
    reasonCodes: [outcome === "ALLOW" ? "ACCESS_ALLOWED" : `${outcome}_REQUIRED`],
    evaluatedAt: "2026-10-13T09:00:00.050Z",
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
    obligations,
  };
}

test("the versioned OPA input accepts complete identity, tenant, role, resource, action, trust and request context", () => {
  const input = decisionInput();
  assert.equal(validateInput(input), true, ajv.errorsText(validateInput.errors));
  assert.deepEqual(Object.keys(input), [
    "schemaVersion",
    "contractId",
    "identity",
    "tenantContext",
    "action",
    "resource",
    "trust",
    "requestContext",
  ]);
});

test("fresh, stale and missing trust states preserve fail-closed policy usability", () => {
  const stale = decisionInput();
  stale.trust = {
    ...freshTrust(),
    state: "stale",
    usableForPolicy: false,
    requiredOutcome: "DENY",
    reasonCode: "TRUST_STATE_STALE",
    policyScore: null,
    policyBand: null,
    ageSeconds: 301,
  };
  assert.equal(validateInput(stale), true, ajv.errorsText(validateInput.errors));

  const missing = decisionInput();
  missing.trust = {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    state: "missing",
    usableForPolicy: false,
    requiredOutcome: "DENY",
    reasonCode: "TRUST_STATE_MISSING",
    policyScore: null,
    policyBand: null,
    lastKnownScore: null,
    lastKnownBand: null,
    ageSeconds: null,
    staleAfterSeconds: null,
    transitionId: null,
    updateVersion: null,
    modelVersion: null,
    configurationVersion: null,
    observedAt: null,
    evaluatedAt: null,
    recordedAt: null,
    explanationHashSha256: null,
  };
  assert.equal(validateInput(missing), true, ajv.errorsText(validateInput.errors));

  stale.trust.policyScore = 72.5;
  assert.equal(validateInput(stale), false, "a stale score became usable policy input");
  missing.trust.usableForPolicy = true;
  assert.equal(validateInput(missing), false, "missing trust became policy-usable");
});

test("invalid identity state remains representable but cannot masquerade as an accepted certificate", () => {
  const input = decisionInput();
  input.identity = {
    ...input.identity,
    valid: false,
    certificateState: "revoked",
    statusSource: "authoritative",
    validUntil: null,
  };
  assert.equal(validateInput(input), true, ajv.errorsText(validateInput.errors));

  input.identity.valid = true;
  assert.equal(validateInput(input), false, "a revoked certificate was marked valid");
});

test("the input rejects incomplete, caller-shaped and unknown authorization fields", () => {
  const cases = [];

  const missingRoles = decisionInput();
  delete missingRoles.tenantContext.roles;
  cases.push(missingRoles);

  const malformedResource = decisionInput();
  malformedResource.resource.resourceIdHashSha256 = "raw-record-id";
  cases.push(malformedResource);

  const unknownAction = decisionInput();
  unknownAction.action = "record:delete-all";
  cases.push(unknownAction);

  const untrustedField = decisionInput();
  untrustedField.clientTenantId = ids.otherTenant;
  cases.push(untrustedField);

  for (const input of cases) {
    assert.equal(validateInput(input), false, "invalid OPA input was accepted");
  }
});

test("the output exposes exactly the four decision outcomes with matching obligations", () => {
  for (const outcome of ["ALLOW", "STEP_UP", "DENY", "QUARANTINE"]) {
    const output = decisionOutput(outcome);
    assert.equal(validateOutput(output), true, `${outcome}: ${ajv.errorsText(validateOutput.errors)}`);
  }
});

test("outcome obligations cannot turn a denial into access or silently omit a required action", () => {
  const allowWithStepUp = decisionOutput("ALLOW");
  allowWithStepUp.obligations.stepUp = {
    required: true,
    binding: ["tenant", "subject", "action", "session"],
    maximumAgeSeconds: 300,
  };
  assert.equal(validateOutput(allowWithStepUp), false);

  const stepUpWithoutChallenge = decisionOutput("STEP_UP");
  stepUpWithoutChallenge.obligations.stepUp = null;
  assert.equal(validateOutput(stepUpWithoutChallenge), false);

  const quarantineWithoutAction = decisionOutput("QUARANTINE");
  quarantineWithoutAction.obligations.quarantine = null;
  assert.equal(validateOutput(quarantineWithoutAction), false);

  const unknownOutcome = decisionOutput("ALLOW");
  unknownOutcome.outcome = "PERMIT";
  assert.equal(validateOutput(unknownOutcome), false);
});

test("the decision output requires policy, input and versioned state provenance", () => {
  const output = decisionOutput("DENY");
  delete output.policy.bundleHashSha256;
  assert.equal(validateOutput(output), false);

  const badInputHash = decisionOutput("DENY");
  badInputHash.input.hashSha256 = "not-a-digest";
  assert.equal(validateOutput(badInputHash), false);

  const missingTrustVersion = decisionOutput("DENY");
  delete missingTrustVersion.state.trustUpdateVersion;
  assert.equal(validateOutput(missingTrustVersion), false);
});
