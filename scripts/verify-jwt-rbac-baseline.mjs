import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  EVALUATION_COMPARISON_SCOPE,
  EVALUATION_RESOURCES,
  EVALUATION_SUBJECTS,
  EVALUATION_WORKLOAD,
  createJwtRbacEvaluationBaseline,
  createJwtRbacEvaluationTokenIssuer,
} from "../packages/evaluation/src/index.mjs";

const clock = () => new Date("2026-10-28T08:00:00.000Z");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
let tokenSequence = 100;
const shared = {
  keyId: "evaluation-key-v1",
  issuer: "tenant-trust-evaluation",
  audience: "tenant-trust-api",
  clock,
};
const issuer = createJwtRbacEvaluationTokenIssuer({
  privateKey,
  ...shared,
  idFactory: () => `018f1234-5678-7abc-8def-${String(tokenSequence++).padStart(12, "0")}`,
});
const baseline = createJwtRbacEvaluationBaseline({ publicKey, ...shared });
const subjects = new Map(EVALUATION_SUBJECTS.map((subject) => [subject.subjectId, subject]));
const tokens = new Map(EVALUATION_SUBJECTS.map((subject) => [subject.subjectId, issuer.issue({
  tenantId: subject.tenantId,
  subjectId: subject.subjectId,
  roles: [subject.role],
}).token]));

function authority(subject) {
  return {
    tenant: { tenantId: subject.tenantId, state: "active", version: 4 },
    subject: { subjectId: subject.subjectId, state: "active", version: 3 },
    membership: { tenantId: subject.tenantId, subjectId: subject.subjectId, state: "active", version: 6 },
  };
}

const results = EVALUATION_WORKLOAD.map((workloadCase) => {
  const actor = subjects.get(workloadCase.actorSubjectId);
  const decision = baseline.authorize({
    token: tokens.get(actor.subjectId),
    authority: authority(actor),
    action: workloadCase.action,
    resource: EVALUATION_RESOURCES[workloadCase.resourceKey],
  });
  assert.equal(decision.outcome, workloadCase.expectedJwtOutcome, workloadCase.workloadCaseId);
  assert.equal(decision.reasonCode, workloadCase.expectedJwtReason, workloadCase.workloadCaseId);
  return decision;
});

assert.equal(EVALUATION_COMPARISON_SCOPE.modes.length, 3);
assert.ok(EVALUATION_COMPARISON_SCOPE.modes.every(({ workloadId }) => (
  workloadId === EVALUATION_COMPARISON_SCOPE.workloadId
)));
assert.equal(results.filter(({ outcome }) => outcome === "allow").length, 10);
assert.equal(results.filter(({ outcome }) => outcome === "deny").length, 4);
assert.ok(results.every((decision) => decision.adaptiveTrustUsed === false));
assert.ok(results.every((decision) => !("certificatePolicy" in decision)));

console.log("PASS Baseline A verifies bounded EdDSA JWT identity and signed RBAC role claims");
console.log("PASS Baseline A, Baseline B and the proposed framework share one two-tenant workload catalog");
console.log("PASS member ownership, tenant administration and Alpha/Beta isolation outcomes match the JWT RBAC oracle");
console.log("PASS JWT baseline remains evaluation-only and does not enter the production mTLS API path");
