import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  createOpaPolicyDecisionClient,
  createPolicyDecisionProvenance,
  hashPolicyInput,
} from "../apps/api/src/index.mjs";
import { createSlide14PrototypePolicyData } from "../services/policy/src/index.mjs";
import { buildTrustTransitionExplanation } from "../services/trust/src/index.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const scenario = JSON.parse(readFileSync(
  new URL("../tests/fixtures/policy/adaptive-authorization-scenario-v1.json", import.meta.url),
  "utf8",
));
const baseInput = JSON.parse(readFileSync(
  new URL("../tests/fixtures/policy/slide14-profile-read.json", import.meta.url),
  "utf8",
));
const runtimeData = JSON.parse(readFileSync(new URL("../policies/data.json", import.meta.url), "utf8"));

const TOP_LEVEL_FIELDS = [
  "baseline", "calibrationStatus", "certificateId", "effectivenessClaim", "fixtureId",
  "issuerId", "requests", "riskyEvidence", "schemaVersion", "subjectId", "tenantId",
  "trustConfiguration",
];
const STAGE_FIELDS = [
  "causationId", "components", "correlationId", "criticalEvidence", "evaluatedSecondsBeforeRun",
  "eventId", "evidenceReferences", "expected", "observedSecondsBeforeRun", "source",
  "transitionId", "updateVersion",
];

function exactFields(value, fields, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort(), `${label} has an unexpected shape`);
}

function isoAt(runTime, secondsBefore) {
  return new Date(runTime.getTime() - secondsBefore * 1_000).toISOString();
}

function previousTransition(record) {
  return {
    transitionId: record.transitionId,
    updateVersion: record.updateVersion,
    score: record.newState.score,
    band: record.newState.band,
    recoveryStreak: record.newState.recoveryStreak,
    temporalState: record.newState.temporalState,
  };
}

function buildTransition(stage, runTime, previous = null) {
  return buildTrustTransitionExplanation({
    transitionId: stage.transitionId,
    eventId: stage.eventId,
    producer: { service: "trust-engine", instanceId: "adaptive-authorization-scenario" },
    evaluatedAt: isoAt(runTime, stage.evaluatedSecondsBeforeRun),
    input: {
      tenantId: scenario.tenantId,
      subjectId: scenario.subjectId,
      updateVersion: stage.updateVersion,
      correlationId: stage.correlationId,
      causationId: stage.causationId,
      components: stage.components,
      evidenceReferences: stage.evidenceReferences,
      configuration: scenario.trustConfiguration,
      observedAt: isoAt(runTime, stage.observedSecondsBeforeRun),
      source: stage.source,
      criticalEvidence: stage.criticalEvidence,
    },
    previousTransition: previous,
  });
}

function assertTransition(record, expected, label) {
  assert.equal(record.weightedScore, expected.weightedScore, `${label} weighted score`);
  assert.equal(record.smoothedScore, expected.smoothedScore, `${label} smoothed score`);
  assert.equal(record.newState.score, expected.score, `${label} controlled score`);
  assert.equal(record.newState.band, expected.band, `${label} trust band`);
  assert.equal(record.transition, expected.transition, `${label} transition`);
}

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

function validStepUp(request, requestedAt, runTime) {
  return {
    status: "valid",
    proofIdHashSha256: request.proofIdHashSha256,
    tenantId: scenario.tenantId,
    subjectId: scenario.subjectId,
    action: request.action,
    sessionIdHashSha256: "abababababababababababababababababababababababababababababababab",
    verifiedAt: isoAt(runTime, 60),
    expiresAt: new Date(Date.parse(requestedAt) + 240_000).toISOString(),
  };
}

function policyInput({ request, transition, requestedAt, runTime }) {
  const input = structuredClone(baseInput);
  const isExport = request.action === "record:export";
  input.identity = {
    ...input.identity,
    authenticationId: `sha256:${"a".repeat(64)}`,
    tenantId: scenario.tenantId,
    subjectId: scenario.subjectId,
    certificateId: scenario.certificateId,
    issuerId: scenario.issuerId,
    serialNumber: "00000000000000000000000000000021",
    fingerprintSha256: "b".repeat(64),
    valid: true,
    certificateState: "active",
    statusSource: "authoritative",
    statusVersion: 7,
    statusObservedAt: requestedAt,
    checkedAt: requestedAt,
    validUntil: new Date(Date.parse(requestedAt) + 300_000).toISOString(),
  };
  input.tenantContext = {
    tenantId: scenario.tenantId,
    subjectId: scenario.subjectId,
    roles: ["tenant-admin"],
    tenantState: "active",
    subjectState: "active",
    membershipState: "active",
    versions: { tenant: 2, subject: 3, membership: 4 },
  };
  input.action = request.action;
  input.resource = {
    tenantId: scenario.tenantId,
    resourceType: isExport ? "tenant-record-export" : "subject-profile",
    resourceIdHashSha256: isExport ? "c".repeat(64) : "d".repeat(64),
    sensitivity: isExport ? "sensitive" : "confidential",
    scope: isExport ? "tenant" : "self",
    ownerSubjectId: isExport ? null : scenario.subjectId,
  };
  input.trust = {
    tenantId: scenario.tenantId,
    subjectId: scenario.subjectId,
    state: "fresh",
    usableForPolicy: true,
    requiredOutcome: null,
    reasonCode: null,
    policyScore: transition.newState.score,
    policyBand: transition.newState.band,
    lastKnownScore: transition.newState.score,
    lastKnownBand: transition.newState.band,
    ageSeconds: (Date.parse(requestedAt) - Date.parse(transition.observedAt)) / 1_000,
    staleAfterSeconds: scenario.trustConfiguration.staleAfterSeconds,
    transitionId: transition.transitionId,
    updateVersion: transition.updateVersion,
    modelVersion: transition.modelVersion,
    configurationVersion: transition.configurationVersion,
    observedAt: transition.observedAt,
    evaluatedAt: transition.evaluatedAt,
    recordedAt: transition.evaluatedAt,
    explanationHashSha256: transition.explanationHashSha256,
  };
  input.requestContext = {
    requestId: request.requestId,
    correlationId: request.correlationId,
    requestedAt,
    method: isExport ? "POST" : "GET",
    routeTemplate: isExport ? "/v1/tenant-records/export" : "/v1/profile",
    sourceNetworkZone: "external",
    stepUp: isExport ? validStepUp(request, requestedAt, runTime) : absentStepUp(),
  };
  return input;
}

exactFields(scenario, TOP_LEVEL_FIELDS, "scenario");
exactFields(scenario.baseline, STAGE_FIELDS, "baseline stage");
exactFields(scenario.riskyEvidence, STAGE_FIELDS, "risky-evidence stage");
assert.equal(scenario.schemaVersion, "1.0.0");
assert.equal(scenario.fixtureId, "adaptive-authorization-scenario-v1");
assert.equal(scenario.calibrationStatus, "UNVALIDATED_PROTOTYPE_DEFAULTS");
assert.equal(scenario.effectivenessClaim, false);
assert.notEqual(
  scenario.baseline.evidenceReferences.find(({ evidenceType }) => evidenceType === "behaviour").evidenceId,
  scenario.riskyEvidence.evidenceReferences.find(({ evidenceType }) => evidenceType === "behaviour").evidenceId,
  "the risky stage must contain new behaviour evidence",
);

const runTime = new Date();
const baselineTransition = buildTransition(scenario.baseline, runTime);
const riskyTransition = buildTransition(
  scenario.riskyEvidence,
  runTime,
  previousTransition(baselineTransition),
);
assertTransition(baselineTransition, scenario.baseline.expected, "baseline");
assertTransition(riskyTransition, scenario.riskyEvidence.expected, "risky evidence");
assert.equal(riskyTransition.previousTransitionId, baselineTransition.transitionId);
assert.equal(riskyTransition.explanation.transitionControl.criticalOverride.kind, "account-takeover-pattern");
assert.equal(riskyTransition.explanation.transitionControl.sourceInfluence.bypassedForCriticalDeterioration, true);
const riskyBehaviourContribution = riskyTransition.contributions
  .find(({ componentId }) => componentId === "behaviour");
assert.equal(riskyBehaviourContribution.normalizedValue, 0);
assert.equal(riskyBehaviourContribution.weightedContribution, 0);
assert.equal(
  riskyBehaviourContribution.evidenceId,
  scenario.riskyEvidence.evidenceReferences.find(({ evidenceType }) => evidenceType === "behaviour").evidenceId,
);

const requestedTimes = {
  normalAccess: isoAt(runTime, 15),
  baselineExport: isoAt(runTime, 10),
  restrictedExport: isoAt(runTime, 5),
};
const cases = [
  {
    id: "normal-access",
    request: scenario.requests.normalAccess,
    transition: baselineTransition,
    requestedAt: requestedTimes.normalAccess,
  },
  {
    id: "baseline-export",
    request: scenario.requests.baselineExport,
    transition: baselineTransition,
    requestedAt: requestedTimes.baselineExport,
  },
  {
    id: "restricted-export",
    request: scenario.requests.restrictedExport,
    transition: riskyTransition,
    requestedAt: requestedTimes.restrictedExport,
  },
].map((item) => ({ ...item, input: policyInput({ ...item, runTime }) }));

assert.ok(cases.every(({ input }) => input.identity.certificateId === scenario.certificateId));
assert.ok(cases.every(({ input }) => input.identity.valid && input.identity.certificateState === "active"));
assert.notEqual(
  cases[1].input.requestContext.stepUp.proofIdHashSha256,
  cases[2].input.requestContext.stepUp.proofIdHashSha256,
  "the scenario must not reuse a one-time step-up proof",
);

const policyConfiguration = createSlide14PrototypePolicyData({ tenantId: scenario.tenantId })
  .tenant_trust_policy.authorization.configuration;
assert.deepEqual(policyConfiguration, runtimeData.tenant_trust_policy.authorization.configuration);
const evaluationInput = cases.map(({ id, input }) => ({ id, input, configuration: policyConfiguration }));
const query = `[
  {"id": selected.id, "decision": decision} |
  some selected in input.cases
  selected_input := selected.input
  configuration := selected.configuration
  decision := data.tenant_trust.authorization.decision
    with input as selected_input
    with data.tenant_trust_policy.authorization.configuration as configuration
]`;
const evaluation = spawnSync("docker", [
  "compose",
  "--env-file", ".env",
  "-f", "infra/compose/compose.yaml",
  "--profile", "tools",
  "run", "--rm", "--no-deps",
  "--entrypoint", "/opa",
  "opa-test",
  "eval",
  "--stdin-input",
  "--format", "json",
  "--data", "/policies",
  query,
], {
  cwd: projectRoot,
  encoding: "utf8",
  input: JSON.stringify({ cases: evaluationInput }),
  maxBuffer: 8 * 1024 * 1024,
});
if (evaluation.error) throw evaluation.error;
assert.equal(evaluation.status, 0, evaluation.stderr || evaluation.stdout);
const evaluated = JSON.parse(evaluation.stdout).result?.[0]?.expressions?.[0]?.value;
assert.ok(Array.isArray(evaluated) && evaluated.length === cases.length, "OPA did not evaluate every scenario request");
const rawDecisions = new Map(evaluated.map(({ id, decision }) => [id, decision]));
const policyRuntime = runtimeData.tenant_trust_policy.authorization.runtime.policy;
const policyBundle = {
  policyVersionId: policyRuntime.policyVersionId,
  bundleVersion: policyRuntime.bundleVersion,
  bundleHashSha256: policyRuntime.bundleHashSha256,
  entrypoint: policyRuntime.decisionPath,
};
const results = new Map();
for (const item of cases) {
  const rawDecision = rawDecisions.get(item.id);
  assert.ok(rawDecision, `OPA omitted ${item.id}`);
  const client = createOpaPolicyDecisionClient({
    baseUrl: "http://opa.verify.internal:8181",
    fetchImpl: async () => ({ ok: true, json: async () => ({ result: rawDecision }) }),
  });
  const decision = await client.decide(item.input);
  assert.equal(decision.outcome, item.request.expectedOutcome, `${item.id} outcome`);
  assert.deepEqual(decision.reasonCodes, [item.request.expectedReasonCode], `${item.id} reason`);
  assert.equal(decision.input.hashSha256, hashPolicyInput(item.input), `${item.id} input hash`);
  assert.equal(decision.state.trustTransitionId, item.transition.transitionId, `${item.id} transition binding`);
  assert.equal(decision.state.trustUpdateVersion, item.transition.updateVersion, `${item.id} version binding`);
  const provenance = createPolicyDecisionProvenance({
    decision,
    input: item.input,
    inputHash: decision.input.hashSha256,
    policyBundle,
  });
  assert.equal(provenance.document.identityState.certificateId, scenario.certificateId);
  assert.equal(provenance.document.trustState.explanationHashSha256, item.transition.explanationHashSha256);
  results.set(item.id, { decision, provenance });
}

assert.equal(results.get("normal-access").decision.outcome, "ALLOW");
assert.equal(results.get("baseline-export").decision.outcome, "ALLOW");
const restricted = results.get("restricted-export");
assert.equal(restricted.decision.outcome, "QUARANTINE");
assert.equal(
  restricted.decision.obligations.quarantine.actionType,
  scenario.requests.restrictedExport.expectedActionType,
);
assert.equal(restricted.provenance.document.trustState.transitionId, riskyTransition.transitionId);
assert.equal(restricted.provenance.document.decision.outcome, "QUARANTINE");
assert.equal(restricted.provenance.canonicalJson.includes(riskyBehaviourContribution.evidenceId), false);

console.log("PASS one valid certificate receives normal profile access and a step-up-bound sensitive export ALLOW");
console.log("PASS new behaviour evidence produces an explainable critical override from trust 69 to 20");
console.log("PASS the same certificate is then quarantined from sensitive export with TRUST_SCORE_QUARANTINE");
console.log("PASS each result satisfies the API contract and canonical provenance binds its trust explanation and policy input");
console.log("LIMIT this deterministic prototype scenario verifies implementation behavior, not real-world detection effectiveness");
