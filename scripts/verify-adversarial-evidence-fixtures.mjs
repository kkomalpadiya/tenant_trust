import assert from "node:assert/strict";
import {
  createEvidenceIngestionService,
  createEvidenceProtector,
  createInMemoryEvidenceReplayGuard,
  EvidenceRejectedError,
} from "@tenant-trust/evidence";
import {
  DEMO_EVIDENCE_SOURCE_CATALOG,
  generateAdversarialEvidenceFixtureSet,
} from "@tenant-trust/evidence-simulators";

const observedAt = "2026-10-06T08:00:00.000Z";
const clock = () => new Date("2026-10-06T08:00:01.000Z");
const fixture = generateAdversarialEvidenceFixtureSet({ observedAt });
const replay = generateAdversarialEvidenceFixtureSet({ observedAt });
assert.deepEqual(replay, fixture);

function scenario(id) {
  const selected = fixture.scenarios.find((candidate) => candidate.id === id);
  assert.ok(selected, `Missing adversarial scenario ${id}.`);
  return selected;
}

function maximumAgeFor(sourceId) {
  for (const tenant of Object.values(DEMO_EVIDENCE_SOURCE_CATALOG)) {
    const source = tenant.sources.find((candidate) => candidate.sourceId === sourceId);
    if (source) return source.maximumAgeSeconds;
  }
  return null;
}

function activeContext(envelope, selectedScenario) {
  const enrollment = selectedScenario.enrollments.find((candidate) => (
    candidate.sourceId === envelope.sourceId && candidate.keyId === envelope.signature.keyId
  ));
  if (!enrollment || enrollment.tenantId !== envelope.tenantId) return null;
  return {
    tenantId: enrollment.tenantId,
    subjectId: envelope.subjectId,
    sourceId: enrollment.sourceId,
    evidenceType: enrollment.evidenceType,
    sourceSynthetic: enrollment.synthetic,
    maximumAgeSeconds: maximumAgeFor(enrollment.sourceId),
    sourceState: "active",
    verificationAlgorithm: enrollment.algorithm,
    keyId: enrollment.keyId,
    keyState: "active",
    keyVersion: 1,
    publicKeyBase64Url: enrollment.publicKeyBase64Url,
    publicKeySha256: enrollment.publicKeySha256,
    keyEnrolledAt: "2026-01-01T00:00:00.000Z",
  };
}

function createScenarioService(selectedScenario, safeguards) {
  const replayGuard = createInMemoryEvidenceReplayGuard({ clock, safeguards });
  const protector = createEvidenceProtector({
    masterKeyBase64Url: Buffer.alloc(32, 7).toString("base64url"),
    encryptionKeyId: "adversarial-fixture-v1",
  });
  return {
    replayGuard,
    service: createEvidenceIngestionService({
      protectEvidence: protector.protect,
      applyReplayGuard: replayGuard,
      async resolveVerificationContext(binding) {
        if (selectedScenario.id === "revoked-source") return null;
        const envelope = selectedScenario.envelopes.find((candidate) => (
          candidate.tenantId === binding.tenantId
          && candidate.subjectId === binding.subjectId
          && candidate.sourceId === binding.sourceId
          && candidate.signature.keyId === binding.keyId
        ));
        return envelope ? activeContext(envelope, selectedScenario) : null;
      },
    }),
  };
}

async function rejectionReason(service, envelope) {
  try {
    await service.ingest({ envelope });
    return null;
  } catch (error) {
    assert.ok(error instanceof EvidenceRejectedError);
    return error.reasonCode;
  }
}

const forged = scenario("forged-signature");
assert.equal(
  await rejectionReason(createScenarioService(forged).service, forged.envelopes[0]),
  forged.expectedOutcome.reasonCode,
);
console.log("PASS foreign-key signature forgery is contract-shaped but fails Ed25519 source authentication");

for (const id of ["revoked-source", "mixed-tenants"]) {
  const selected = scenario(id);
  assert.equal(
    await rejectionReason(createScenarioService(selected).service, selected.envelopes[0]),
    selected.expectedOutcome.reasonCode,
  );
}
console.log("PASS revoked source authority and mixed-tenant bindings resolve to no trusted verification context");

const missing = scenario("missing-signals");
const missingService = createScenarioService(missing).service;
for (const envelope of missing.envelopes) {
  assert.equal((await missingService.ingest({ envelope })).status, "accepted");
}
const absentTypes = missing.requiredEvidenceTypes.filter(
  (type) => !missing.envelopes.some((envelope) => envelope.evidenceType === type),
);
assert.deepEqual(absentTypes, missing.missingEvidenceTypes);
assert.equal(missing.expectedOutcome.decision, "withhold");
console.log("PASS partial valid evidence identifies behaviour and compliance as missing before trust-state use");

const duplicate = scenario("duplicate-event-id");
const duplicateService = createScenarioService(duplicate).service;
assert.equal((await duplicateService.ingest({ envelope: duplicate.envelopes[0] })).status, "accepted");
assert.equal(
  await rejectionReason(duplicateService, duplicate.envelopes[1]),
  duplicate.expectedOutcomes[1].reasonCode,
);
console.log("PASS independently signed reuse of one event ID is rejected as a replay after the first acceptance");

const flood = scenario("event-flood");
const floodRuntime = createScenarioService(flood, flood.safeguards);
const floodOutcomes = [];
for (const envelope of flood.envelopes) {
  const reasonCode = await rejectionReason(floodRuntime.service, envelope);
  floodOutcomes.push(reasonCode ?? "ACCEPTED");
}
assert.deepEqual(floodOutcomes, [
  "ACCEPTED", "ACCEPTED", "ACCEPTED", "ACCEPTED",
  "EVIDENCE_RATE_LIMITED", "EVIDENCE_RATE_LIMITED", "VERIFICATION_CONTEXT_NOT_FOUND",
]);
const sourceControl = floodRuntime.replayGuard.snapshot().sourceControls[0];
assert.equal(sourceControl.suspended, flood.expectedSummary.sourceSuspended);
assert.equal(sourceControl.maximumSourceInfluence, flood.expectedSummary.maximumSourceInfluence);
console.log("PASS bounded event flood reaches quota, records two rate limits and automatically suspends the source");

assert.doesNotMatch(JSON.stringify(fixture), /private|pkcs8|seed/i);
console.log("PASS adversarial suite is deterministic, immutable and exposes no private key material");
