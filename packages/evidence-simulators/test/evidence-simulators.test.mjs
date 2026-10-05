import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as verifyEd25519 } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  canonicalizeEvidenceJson,
  createDeterministicEvidenceSimulator,
  DEMO_EVIDENCE_SOURCE_CATALOG,
  EvidenceSimulatorError,
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
