import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  StepUpAuthenticationError,
  createStepUpChallengeMaterial,
  createStepUpProofMaterial,
  createStepUpSigningPayload,
  hashStepUpValue,
  verifyStepUpChallengeSignature,
} from "../src/index.mjs";

const tenantId = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const subjectId = "sub_018f1234-5678-7abc-8def-0123456789ab";
const factorId = "suf_018f1234-5678-7abc-8def-0123456789ab";
const ids = [
  "018f1234-5678-7abc-8def-0123456789a1",
  "018f1234-5678-7abc-8def-0123456789a2",
  "018f1234-5678-7abc-8def-0123456789a3",
];

function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  const spki = pair.publicKey.export({ type: "spki", format: "der" });
  return { ...pair, publicKeyBase64url: spki.subarray(-32).toString("base64url") };
}

test("a selected Ed25519 factor verifies the exact bound challenge", () => {
  const pair = keyPair();
  let index = 0;
  const challenge = createStepUpChallengeMaterial({
    tenantId,
    subjectId,
    factorId,
    action: "record:export",
    now: "2026-10-20T09:00:00.000Z",
    idFactory: () => ids[index++],
    bytesFactory: () => Buffer.alloc(32, 7),
  });
  const signatureBase64url = sign(null, createStepUpSigningPayload(challenge), pair.privateKey)
    .toString("base64url");

  assert.equal(verifyStepUpChallengeSignature({
    challenge,
    publicKeyBase64url: pair.publicKeyBase64url,
    signatureBase64url,
  }), true);
  assert.equal(challenge.sessionIdHashSha256, hashStepUpValue(challenge.sessionId));
  assert.equal(Date.parse(challenge.expiresAt) - Date.parse(challenge.issuedAt), 120_000);
});

test("tenant, subject, action and session tampering invalidates the signature", () => {
  const pair = keyPair();
  let index = 0;
  const challenge = createStepUpChallengeMaterial({
    tenantId,
    subjectId,
    factorId,
    action: "tenant:admin",
    now: "2026-10-20T09:00:00.000Z",
    idFactory: () => ids[index++],
    bytesFactory: () => Buffer.alloc(32, 9),
  });
  const signatureBase64url = sign(null, createStepUpSigningPayload(challenge), pair.privateKey)
    .toString("base64url");

  for (const tampered of [
    { ...challenge, tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac" },
    { ...challenge, subjectId: "sub_018f1234-5678-7abc-8def-0123456789ac" },
    { ...challenge, action: "record:export" },
    { ...challenge, sessionIdHashSha256: "ab".repeat(32) },
  ]) {
    assert.throws(
      () => verifyStepUpChallengeSignature({
        challenge: tampered,
        publicKeyBase64url: pair.publicKeyBase64url,
        signatureBase64url,
      }),
      StepUpAuthenticationError,
    );
  }
});

test("proof identifiers are opaque, hashed for storage and expire after five minutes", () => {
  const proof = createStepUpProofMaterial({
    now: "2026-10-20T09:00:00.000Z",
    idFactory: () => ids[2],
  });
  assert.match(proof.proofId, /^sup_/u);
  assert.equal(proof.proofIdHashSha256, hashStepUpValue(proof.proofId));
  assert.equal(Date.parse(proof.expiresAt) - Date.parse(proof.verifiedAt), 300_000);
});
