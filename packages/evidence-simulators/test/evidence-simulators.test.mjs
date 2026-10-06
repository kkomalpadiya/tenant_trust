import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as verifyEd25519 } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  ADVERSARIAL_EVIDENCE_SCENARIO_IDS,
  canonicalizeEvidenceJson,
  createDeterministicEvidenceSimulator,
  DEMO_EVIDENCE_SOURCE_CATALOG,
  EvidenceSimulatorError,
  generateAdversarialEvidenceFixtureSet,
  generateDeterministicDemoEvidenceSet,
  unsignedEvidenceEnvelope,
} from "../src/index.mjs";

const schemaRoot = resolve(import.meta.dirname, "../../contracts/schemas");
const common = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const envelopeSchema = JSON.parse(readFileSync(resolve(schemaRoot, "evidence/signed-evidence-envelope.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateEnvelope = ajv.compile(envelopeSchema);

function publicKeyFor(enrollment) {
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: enrollment.publicKeyBase64Url },
    format: "jwk",
  });
}

test("canonical evidence JSON is independent of object insertion order", () => {
  const left = { z: 1, a: { y: true, x: ["one", 2] } };
  const right = { a: { x: ["one", 2], y: true }, z: 1 };
  assert.equal(canonicalizeEvidenceJson(left), '{"a":{"x":["one",2],"y":true},"z":1}');
  assert.equal(canonicalizeEvidenceJson(left), canonicalizeEvidenceJson(right));
});

test("the demo set produces one contract-valid synthetic envelope for every evidence type", () => {
  const fixture = generateDeterministicDemoEvidenceSet();
  assert.deepEqual(fixture.envelopes.map((envelope) => envelope.evidenceType), [
    "identity", "device", "behaviour", "certificate", "compliance",
  ]);
  assert.equal(fixture.enrollments.length, 5);
  for (const envelope of fixture.envelopes) {
    assert.equal(validateEnvelope(envelope), true, ajv.errorsText(validateEnvelope.errors));
    assert.equal(envelope.synthetic, true);
    assert.equal(envelope.payload.provenance.synthetic, true);
  }
  assert.deepEqual(
    fixture.envelopes.map((envelope) => (Date.parse(envelope.expiresAt) - Date.parse(envelope.observedAt)) / 1_000),
    [300, 300, 300, 60, 3600],
  );
});

test("device posture and compliance attestation carry explicit nested synthetic markers", () => {
  const fixture = generateDeterministicDemoEvidenceSet();
  const device = fixture.envelopes.find((envelope) => envelope.evidenceType === "device");
  const compliance = fixture.envelopes.find((envelope) => envelope.evidenceType === "compliance");
  assert.equal(device.payload.posture.synthetic, true);
  assert.equal(compliance.payload.attestation.synthetic, true);
  assert.equal(compliance.payload.attestation.status, "compliant");
});

test("identical inputs reproduce every identifier, nonce, digest and signature", () => {
  const first = generateDeterministicDemoEvidenceSet();
  const second = generateDeterministicDemoEvidenceSet();
  assert.deepEqual(second, first);
  assert.equal(canonicalizeEvidenceJson(second), canonicalizeEvidenceJson(first));
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.envelopes[0].payload), true);
  assert.deepEqual({
    keyId: first.enrollments[0].keyId,
    publicKeySha256: first.enrollments[0].publicKeySha256,
    eventId: first.envelopes[0].eventId,
    nonce: first.envelopes[0].nonce,
    signedContentSha256: first.envelopes[0].signature.signedContentSha256,
    signatureBase64Url: first.envelopes[0].signature.signatureBase64Url,
  }, {
    keyId: "key_99de4409-0767-849d-9874-44b32cd3999b",
    publicKeySha256: "dea89ba1c3cca6f2a38393f2c70d29f460bdd7b8d4b2227a2acee5c13617c8ff",
    eventId: "evt_e14d9e63-35a6-8dd4-a585-879eebcad740",
    nonce: "Ja8uiY0YCB4ZO63eQSjxgmk5",
    signedContentSha256: "ede96891a6ce397cc77c8f163163adc7af0ba489aee3641d29e565a877c35366",
    signatureBase64Url: "WaGi6D2pzhmZ_FzwBMg14e5hvirNIwbM3j51Cdr9qLWorjHPKi78G87ayVmHO8iW22ZiBeGP3daG2czOoT9MBw",
  });
});

test("every signature verifies only with its tenant/source enrollment key", () => {
  const fixture = generateDeterministicDemoEvidenceSet();
  for (let index = 0; index < fixture.envelopes.length; index += 1) {
    const envelope = fixture.envelopes[index];
    const enrollment = fixture.enrollments[index];
    const content = Buffer.from(canonicalizeEvidenceJson(unsignedEvidenceEnvelope(envelope)), "utf8");
    assert.equal(createHash("sha256").update(content).digest("hex"), envelope.signature.signedContentSha256);
    assert.equal(envelope.signature.keyId, enrollment.keyId);
    assert.equal(verifyEd25519(
      null,
      content,
      publicKeyFor(enrollment),
      Buffer.from(envelope.signature.signatureBase64Url, "base64url"),
    ), true);
  }
  const tampered = structuredClone(fixture.envelopes[0]);
  tampered.payload.directoryState = "suspended";
  const tamperedContent = Buffer.from(canonicalizeEvidenceJson(unsignedEvidenceEnvelope(tampered)), "utf8");
  assert.equal(verifyEd25519(
    null,
    tamperedContent,
    publicKeyFor(fixture.enrollments[0]),
    Buffer.from(tampered.signature.signatureBase64Url, "base64url"),
  ), false);
});

test("tenant, observation time and sequence changes produce distinct deterministic fixtures", () => {
  const baseline = generateDeterministicDemoEvidenceSet();
  const beta = generateDeterministicDemoEvidenceSet({ tenantAlias: "beta" });
  const later = generateDeterministicDemoEvidenceSet({ sourceSequence: 2 });
  assert.notEqual(beta.envelopes[0].eventId, baseline.envelopes[0].eventId);
  assert.notEqual(beta.enrollments[0].keyId, baseline.enrollments[0].keyId);
  assert.notEqual(later.envelopes[0].eventId, baseline.envelopes[0].eventId);
  assert.notEqual(later.envelopes[0].nonce, baseline.envelopes[0].nonce);
});

test("fixture output contains public enrollment data but no private key material", () => {
  const fixture = generateDeterministicDemoEvidenceSet();
  const serialized = JSON.stringify(fixture);
  assert.doesNotMatch(serialized, /private|pkcs8|seed/i);
  for (const enrollment of fixture.enrollments) {
    assert.match(enrollment.publicKeyBase64Url, /^[A-Za-z0-9_-]{43}$/u);
    assert.match(enrollment.publicKeySha256, /^[0-9a-f]{64}$/u);
  }
});

test("invalid source configuration and fixture selectors fail explicitly", () => {
  assert.throws(
    () => generateDeterministicDemoEvidenceSet({ tenantAlias: "gamma" }),
    (error) => error instanceof EvidenceSimulatorError && error.reasonCode === "TENANT_ALIAS_INVALID",
  );
  assert.throws(
    () => generateDeterministicDemoEvidenceSet({ observedAt: "2026-10-05 08:00:00" }),
    (error) => error instanceof EvidenceSimulatorError && error.reasonCode === "OBSERVATION_TIME_INVALID",
  );
  assert.throws(
    () => createDeterministicEvidenceSimulator({
      tenantId: DEMO_EVIDENCE_SOURCE_CATALOG.alpha.tenantId,
      sourceId: DEMO_EVIDENCE_SOURCE_CATALOG.alpha.sources[0].sourceId,
      evidenceType: "location",
      maximumAgeSeconds: 300,
    }),
    (error) => error instanceof EvidenceSimulatorError && error.reasonCode === "SIMULATOR_CONFIGURATION_INVALID",
  );
});

function scenarioById(fixture, id) {
  return fixture.scenarios.find((scenario) => scenario.id === id);
}

function verifiesWithEnrollment(envelope, enrollment) {
  const content = Buffer.from(canonicalizeEvidenceJson(unsignedEvidenceEnvelope(envelope)), "utf8");
  return verifyEd25519(
    null,
    content,
    publicKeyFor(enrollment),
    Buffer.from(envelope.signature.signatureBase64Url, "base64url"),
  );
}

test("adversarial suite covers every required threat with explicit expected outcomes", () => {
  const fixture = generateAdversarialEvidenceFixtureSet();
  assert.deepEqual(fixture.scenarios.map(({ id }) => id), ADVERSARIAL_EVIDENCE_SCENARIO_IDS);
  assert.equal(new Set(fixture.scenarios.map(({ attackClass }) => attackClass)).size, 6);
  for (const scenario of fixture.scenarios) {
    assert.ok(scenario.enrollments.length >= 1);
    assert.ok(scenario.envelopes.length >= 1);
  }
  assert.deepEqual(scenarioById(fixture, "missing-signals").missingEvidenceTypes, ["behaviour", "compliance"]);
  assert.equal(scenarioById(fixture, "event-flood").expectedSummary.sourceSuspended, true);
});

test("forged signature remains contract-valid but fails the registered source key", () => {
  const scenario = scenarioById(generateAdversarialEvidenceFixtureSet(), "forged-signature");
  assert.equal(validateEnvelope(scenario.envelopes[0]), true, ajv.errorsText(validateEnvelope.errors));
  assert.equal(verifiesWithEnrollment(scenario.envelopes[0], scenario.enrollments[0]), false);
  const content = Buffer.from(canonicalizeEvidenceJson(unsignedEvidenceEnvelope(scenario.envelopes[0])), "utf8");
  assert.equal(
    createHash("sha256").update(content).digest("hex"),
    scenario.envelopes[0].signature.signedContentSha256,
  );
  assert.deepEqual(scenario.expectedOutcome, {
    decision: "reject",
    reasonCode: "EVIDENCE_SIGNATURE_INVALID",
  });
});

test("revoked-source and mixed-tenant fixtures isolate authority failures from schema failures", () => {
  const fixture = generateAdversarialEvidenceFixtureSet();
  const revoked = scenarioById(fixture, "revoked-source");
  const mixed = scenarioById(fixture, "mixed-tenants");
  assert.equal(validateEnvelope(revoked.envelopes[0]), true, ajv.errorsText(validateEnvelope.errors));
  assert.equal(verifiesWithEnrollment(revoked.envelopes[0], revoked.enrollments[0]), true);
  assert.deepEqual(revoked.authority, { sourceState: "suspended", keyState: "revoked" });
  assert.equal(validateEnvelope(mixed.envelopes[0]), true, ajv.errorsText(validateEnvelope.errors));
  assert.equal(verifiesWithEnrollment(mixed.envelopes[0], mixed.enrollments[0]), true);
  assert.notEqual(mixed.authority.registeredTenantId, mixed.authority.presentedTenantId);
  assert.equal(mixed.envelopes[0].tenantId, mixed.authority.presentedTenantId);
  assert.equal(mixed.enrollments[0].tenantId, mixed.authority.registeredTenantId);
});

test("missing-signal fixture is valid but omits the declared behaviour and compliance types", () => {
  const scenario = scenarioById(generateAdversarialEvidenceFixtureSet(), "missing-signals");
  assert.deepEqual(scenario.envelopes.map(({ evidenceType }) => evidenceType), ["identity", "device", "certificate"]);
  assert.deepEqual(
    scenario.requiredEvidenceTypes.filter((type) => !scenario.envelopes.some((envelope) => envelope.evidenceType === type)),
    scenario.missingEvidenceTypes,
  );
  assert.equal(scenario.envelopes.every((envelope, index) => {
    assert.equal(validateEnvelope(envelope), true, ajv.errorsText(validateEnvelope.errors));
    return verifiesWithEnrollment(envelope, scenario.enrollments[index]);
  }), true);
  assert.deepEqual(scenario.expectedOutcome, {
    decision: "withhold",
    reasonCode: "REQUIRED_EVIDENCE_MISSING",
  });
});

test("duplicate-ID fixture contains two independently valid signatures over conflicting events", () => {
  const scenario = scenarioById(generateAdversarialEvidenceFixtureSet(), "duplicate-event-id");
  const [first, second] = scenario.envelopes;
  assert.equal(first.eventId, second.eventId);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.sourceSequence, second.sourceSequence);
  assert.notEqual(first.signature.signedContentSha256, second.signature.signedContentSha256);
  assert.equal(verifiesWithEnrollment(first, scenario.enrollments[0]), true);
  assert.equal(verifiesWithEnrollment(second, scenario.enrollments[0]), true);
  assert.deepEqual(scenario.expectedOutcomes.map(({ reasonCode }) => reasonCode), [null, "EVIDENCE_EVENT_REPLAYED"]);
});

test("event-flood fixture is ordered and carries its bounded safeguard oracle", () => {
  const scenario = scenarioById(generateAdversarialEvidenceFixtureSet(), "event-flood");
  assert.equal(scenario.envelopes.length, 7);
  assert.deepEqual(scenario.envelopes.map(({ sourceSequence }) => sourceSequence), [200, 201, 202, 203, 204, 205, 206]);
  assert.equal(new Set(scenario.envelopes.map(({ eventId }) => eventId)).size, 7);
  assert.equal(scenario.envelopes.every((envelope) => verifiesWithEnrollment(envelope, scenario.enrollments[0])), true);
  assert.deepEqual(scenario.expectedSummary, {
    acceptedCount: 4,
    rateLimitedCount: 2,
    finalReasonCode: "VERIFICATION_CONTEXT_NOT_FOUND",
    sourceSuspended: true,
    maximumSourceInfluence: 0.2,
  });
});

test("adversarial fixtures are deterministic, immutable and contain no private key material", () => {
  const first = generateAdversarialEvidenceFixtureSet();
  const second = generateAdversarialEvidenceFixtureSet();
  assert.deepEqual(second, first);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.scenarios[0].envelopes[0]), true);
  assert.doesNotMatch(JSON.stringify(first), /private|pkcs8|seed/i);
  assert.throws(
    () => generateAdversarialEvidenceFixtureSet({ floodEventCount: 6 }),
    (error) => error instanceof EvidenceSimulatorError && error.reasonCode === "FLOOD_EVENT_COUNT_INVALID",
  );
});
