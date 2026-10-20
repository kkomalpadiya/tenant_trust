import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  createOpaPolicyDecisionClient,
  hashPolicyInput,
} from "../apps/api/src/index.mjs";
import {
  createSlide14PrototypePolicyData,
  validateAdaptiveAuthorizationPolicyData,
} from "../services/policy/src/adaptive-authorization-policy.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const fixturesDirectory = new URL("../tests/fixtures/policy/", import.meta.url);
const matrix = JSON.parse(readFileSync(new URL("adaptive-policy-matrix-v1.json", fixturesDirectory), "utf8"));
const baseInput = JSON.parse(readFileSync(new URL(matrix.baseInputFixture, fixturesDirectory), "utf8"));

const ACTIONS = new Set([
  "profile:read",
  "record:read",
  "record:write",
  "record:export",
  "tenant:admin",
  "member:manage",
  "certificate:manage",
  "admin-key:rotate",
]);
const CATEGORIES = new Set([
  "score-edge",
  "decimal-score",
  "action",
  "role",
  "sensitivity",
  "tenant-policy",
  "expired-step-up",
]);
const OUTCOMES = new Set(["ALLOW", "DENY", "STEP_UP", "QUARANTINE"]);
const PROOFS = new Set(["absent", "valid", "expired"]);
const PROFILE_FIELDS = [
  "id",
  "minimumScoreOverrides",
  "policyProfile",
  "stepUpRequiredOverrides",
  "tenantId",
];
const CASE_FIELDS = [
  "action",
  "categories",
  "expected",
  "id",
  "profile",
  "roles",
  "score",
  "sensitivity",
  "stepUpProof",
];

function exactFields(value, fields, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort(), `${label} has an unexpected shape`);
}

function clone(value) {
  return structuredClone(value);
}

function buildConfiguration(profile) {
  const policyData = clone(createSlide14PrototypePolicyData({ tenantId: profile.tenantId }));
  const configuration = policyData.tenant_trust_policy.authorization.configuration;
  configuration.policyProfile = profile.policyProfile;
  for (const [action, minimumScore] of Object.entries(profile.minimumScoreOverrides)) {
    assert.ok(ACTIONS.has(action), `profile ${profile.id} overrides an unknown action`);
    assert.ok(Number.isFinite(minimumScore), `profile ${profile.id} has a non-numeric score override`);
    configuration.actionRules.find((rule) => rule.action === action).minimumScore = minimumScore;
  }
  for (const action of profile.stepUpRequiredOverrides) {
    assert.ok(ACTIONS.has(action), `profile ${profile.id} overrides step-up for an unknown action`);
    configuration.actionRules.find((rule) => rule.action === action).stepUpRequired = true;
  }
  return validateAdaptiveAuthorizationPolicyData(policyData, profile.tenantId)
    .tenant_trust_policy.authorization.configuration;
}

function tenantBoundInput(testCase, profile, index) {
  const input = clone(baseInput);
  const suffix = (index + 1).toString(16).padStart(12, "0");
  const subjectId = profile.tenantId.endsWith("9ab")
    ? "sub_018f1234-5678-7abc-8def-0123456789ab"
    : "sub_018f1234-5678-7abc-8def-0123456789ad";

  input.identity.tenantId = profile.tenantId;
  input.identity.subjectId = subjectId;
  input.tenantContext.tenantId = profile.tenantId;
  input.tenantContext.subjectId = subjectId;
  input.tenantContext.roles = [...testCase.roles];
  input.resource.tenantId = profile.tenantId;
  input.resource.ownerSubjectId = subjectId;
  input.resource.sensitivity = testCase.sensitivity;
  input.trust.tenantId = profile.tenantId;
  input.trust.subjectId = subjectId;
  input.trust.policyScore = testCase.score;
  input.trust.lastKnownScore = testCase.score;
  input.action = testCase.action;
  input.requestContext.requestId = `req_018f1234-5678-7abc-8def-${suffix}`;
  input.requestContext.correlationId = `cor_018f1234-5678-7abc-8def-${suffix}`;

  if (testCase.stepUpProof === "absent") return input;
  input.requestContext.stepUp = {
    status: "valid",
    proofIdHashSha256: "e".repeat(64),
    tenantId: profile.tenantId,
    subjectId,
    action: testCase.action,
    sessionIdHashSha256: "f".repeat(64),
    verifiedAt: testCase.stepUpProof === "expired"
      ? "2026-10-20T08:50:00.000Z"
      : "2026-10-20T08:59:00.000Z",
    expiresAt: testCase.stepUpProof === "expired"
      ? "2026-10-20T08:59:59.000Z"
      : "2026-10-20T09:04:00.000Z",
  };
  return input;
}

exactFields(matrix, ["baseInputFixture", "cases", "fixtureId", "profiles", "schemaVersion"], "matrix");
assert.equal(matrix.schemaVersion, "1.0.0");
assert.equal(matrix.fixtureId, "adaptive-policy-matrix-v1");
assert.ok(Array.isArray(matrix.profiles) && matrix.profiles.length >= 2, "matrix needs at least two tenant profiles");
assert.ok(Array.isArray(matrix.cases) && matrix.cases.length > 0, "matrix needs decision cases");

const profiles = new Map();
for (const profile of matrix.profiles) {
  exactFields(profile, PROFILE_FIELDS, `profile ${profile.id ?? "<unknown>"}`);
  assert.match(profile.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
  assert.ok(!profiles.has(profile.id), `duplicate profile ${profile.id}`);
  assert.ok(profile.minimumScoreOverrides && typeof profile.minimumScoreOverrides === "object");
  assert.ok(Array.isArray(profile.stepUpRequiredOverrides));
  profiles.set(profile.id, { profile, configuration: buildConfiguration(profile) });
}

const ids = new Set();
const coveredCategories = new Set();
const coveredActions = new Set();
const evaluationCases = matrix.cases.map((testCase, index) => {
  exactFields(testCase, CASE_FIELDS, `case ${testCase.id ?? "<unknown>"}`);
  exactFields(testCase.expected, ["outcome", "reasonCode"], `case ${testCase.id} expected`);
  assert.match(testCase.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
  assert.ok(!ids.has(testCase.id), `duplicate case ${testCase.id}`);
  ids.add(testCase.id);
  assert.ok(Array.isArray(testCase.categories) && testCase.categories.length > 0);
  for (const category of testCase.categories) {
    assert.ok(CATEGORIES.has(category), `case ${testCase.id} has unknown category ${category}`);
    coveredCategories.add(category);
  }
  assert.ok(ACTIONS.has(testCase.action), `case ${testCase.id} has an unknown action`);
  coveredActions.add(testCase.action);
  assert.ok(Number.isFinite(testCase.score) && testCase.score >= 0 && testCase.score <= 100);
  assert.ok(Array.isArray(testCase.roles) && testCase.roles.length > 0);
  assert.ok(PROOFS.has(testCase.stepUpProof));
  assert.ok(OUTCOMES.has(testCase.expected.outcome));
  assert.match(testCase.expected.reasonCode, /^[A-Z][A-Z0-9_]+$/u);
  const selected = profiles.get(testCase.profile);
  assert.ok(selected, `case ${testCase.id} references unknown profile ${testCase.profile}`);
  return {
    id: testCase.id,
    expected: testCase.expected,
    input: tenantBoundInput(testCase, selected.profile, index),
    configuration: selected.configuration,
  };
});

assert.deepEqual([...coveredCategories].sort(), [...CATEGORIES].sort(), "matrix category coverage is incomplete");
assert.deepEqual([...coveredActions].sort(), [...ACTIONS].sort(), "matrix action coverage is incomplete");
assert.ok(matrix.cases.some((testCase) => !Number.isInteger(testCase.score)), "matrix needs decimal scores");
assert.ok(matrix.cases.some((testCase) => testCase.score === 100), "matrix needs the maximum score boundary");
assert.ok(matrix.cases.some((testCase) => testCase.stepUpProof === "expired"), "matrix needs an expired proof");

const query = `[
  {"id": case.id, "decision": decision} |
  some case in input.cases
  case_input := case.input
  configuration := case.configuration
  decision := data.tenant_trust.authorization.decision
    with input as case_input
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
  input: JSON.stringify({ cases: evaluationCases }),
  maxBuffer: 8 * 1024 * 1024,
});

if (evaluation.error) throw evaluation.error;
assert.equal(evaluation.status, 0, evaluation.stderr || evaluation.stdout);
const document = JSON.parse(evaluation.stdout);
const results = document.result?.[0]?.expressions?.[0]?.value;
assert.ok(Array.isArray(results), "OPA did not return the policy matrix results");
assert.equal(results.length, evaluationCases.length, "OPA did not evaluate every matrix case");
const decisions = new Map(results.map(({ id, decision }) => [id, decision]));
assert.equal(decisions.size, evaluationCases.length, "OPA returned duplicate or missing matrix case identifiers");

for (const testCase of evaluationCases) {
  const decision = decisions.get(testCase.id);
  assert.ok(decision, `OPA did not return decision ${testCase.id}`);
  const client = createOpaPolicyDecisionClient({
    baseUrl: "http://opa.verify.internal:8181",
    fetchImpl: async () => ({ ok: true, json: async () => ({ result: decision }) }),
  });
  const validated = await client.decide(testCase.input);
  assert.equal(validated.outcome, testCase.expected.outcome, `${testCase.id} outcome`);
  assert.deepEqual(validated.reasonCodes, [testCase.expected.reasonCode], `${testCase.id} reason`);
  assert.equal(validated.input.hashSha256, hashPolicyInput(testCase.input), `${testCase.id} input hash`);
  assert.equal(validated.tenantId, testCase.input.tenantContext.tenantId, `${testCase.id} tenant binding`);
  assert.equal(validated.subjectId, testCase.input.tenantContext.subjectId, `${testCase.id} subject binding`);
  assert.equal(validated.state.trustUpdateVersion, testCase.input.trust.updateVersion, `${testCase.id} trust binding`);
  assert.equal(validated.obligations.stepUp?.required === true, validated.outcome === "STEP_UP", `${testCase.id} step-up obligation`);
  assert.equal(validated.obligations.quarantine?.required === true, validated.outcome === "QUARANTINE", `${testCase.id} quarantine obligation`);
}

const pairedOutcomes = new Map(evaluationCases.map(({ id }) => [id, decisions.get(id).outcome]));
assert.equal(pairedOutcomes.get("alpha-profile-read-at-57"), "ALLOW");
assert.equal(pairedOutcomes.get("beta-profile-read-at-57"), "DENY");
assert.equal(pairedOutcomes.get("alpha-record-read-at-60"), "ALLOW");
assert.equal(pairedOutcomes.get("beta-record-read-requires-step-up"), "STEP_UP");

console.log(`PASS ${evaluationCases.length} fixture-driven OPA decisions cover every adaptive-policy action`);
console.log("PASS exact and decimal score boundaries, roles, and resource sensitivities are enforced");
console.log("PASS valid tenant-specific policies produce intentionally different decisions for identical request conditions");
console.log("PASS expired step-up proof returns STEP_UP and every decision satisfies the API output contract");
