import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as verifyEd25519 } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  canonicalizeEvidenceJson,
  generateDeterministicDemoEvidenceSet,
  unsignedEvidenceEnvelope,
} from "../packages/evidence-simulators/src/index.mjs";

const schemaRoot = resolve(import.meta.dirname, "../packages/contracts/schemas");
const common = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const envelopeSchema = JSON.parse(readFileSync(resolve(schemaRoot, "evidence/signed-evidence-envelope.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateEnvelope = ajv.compile(envelopeSchema);

const first = generateDeterministicDemoEvidenceSet();
const replay = generateDeterministicDemoEvidenceSet();
assert.deepEqual(replay, first);
assert.equal(first.envelopes.length, 5);
assert.equal(first.enrollments.length, 5);
console.log("PASS identical simulator inputs reproduce the complete five-signal fixture set");

for (let index = 0; index < first.envelopes.length; index += 1) {
  const envelope = first.envelopes[index];
  const enrollment = first.enrollments[index];
  assert.equal(validateEnvelope(envelope), true, ajv.errorsText(validateEnvelope.errors));
  const content = Buffer.from(canonicalizeEvidenceJson(unsignedEvidenceEnvelope(envelope)), "utf8");
  assert.equal(createHash("sha256").update(content).digest("hex"), envelope.signature.signedContentSha256);
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: enrollment.publicKeyBase64Url },
    format: "jwk",
  });
  assert.equal(verifyEd25519(
    null,
    content,
    publicKey,
    Buffer.from(envelope.signature.signatureBase64Url, "base64url"),
  ), true);
}
console.log("PASS identity, device, behaviour, certificate and compliance envelopes satisfy the signed contract");
console.log("PASS every canonical digest and Ed25519 signature verifies with its tenant/source enrollment key");

const device = first.envelopes.find((envelope) => envelope.evidenceType === "device");
const compliance = first.envelopes.find((envelope) => envelope.evidenceType === "compliance");
assert.equal(first.envelopes.every((envelope) => envelope.synthetic && envelope.payload.provenance.synthetic), true);
assert.equal(device.payload.posture.synthetic, true);
assert.equal(compliance.payload.attestation.synthetic, true);
console.log("PASS all claims are synthetic and posture/compliance carry explicit nested markers");

const beta = generateDeterministicDemoEvidenceSet({ tenantAlias: "beta" });
assert.notEqual(beta.tenantId, first.tenantId);
assert.equal(beta.envelopes.every((envelope) => envelope.tenantId === beta.tenantId), true);
assert.equal(beta.enrollments.every((enrollment) => enrollment.tenantId === beta.tenantId), true);
assert.notEqual(beta.enrollments[0].keyId, first.enrollments[0].keyId);
console.log("PASS Alpha and Beta fixture identities, sources and public keys remain tenant-separated");
