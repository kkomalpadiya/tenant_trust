import { createHash, createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";

export const STEP_UP_POLICY = Object.freeze({
  algorithm: "Ed25519",
  challengeLifetimeSeconds: 120,
  proofLifetimeSeconds: 300,
  supportedActions: Object.freeze(["record:export", "tenant:admin"]),
});

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
export const STEP_UP_FACTOR_ID_PATTERN = `^suf_${UUID}$`;
export const STEP_UP_CHALLENGE_ID_PATTERN = `^suc_${UUID}$`;
export const STEP_UP_PROOF_ID_PATTERN = `^sup_${UUID}$`;
export const STEP_UP_SESSION_ID_PATTERN = `^sus_${UUID}$`;
export const STEP_UP_SIGNATURE_PATTERN = "^[A-Za-z0-9_-]{86}$";

const FACTOR_ID = new RegExp(STEP_UP_FACTOR_ID_PATTERN, "u");
const CHALLENGE_ID = new RegExp(STEP_UP_CHALLENGE_ID_PATTERN, "u");
const PROOF_ID = new RegExp(STEP_UP_PROOF_ID_PATTERN, "u");
const SESSION_ID = new RegExp(STEP_UP_SESSION_ID_PATTERN, "u");
const SIGNATURE = new RegExp(STEP_UP_SIGNATURE_PATTERN, "u");
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const HASH = /^[0-9a-f]{64}$/u;
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class StepUpAuthenticationError extends Error {
  constructor(reasonCode = "STEP_UP_AUTHENTICATION_FAILED") {
    super("Step-up authentication failed.");
    this.name = "StepUpAuthenticationError";
    this.reasonCode = reasonCode;
  }
}

export function hashStepUpValue(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 255) {
    throw new StepUpAuthenticationError("STEP_UP_PRESENTATION_INVALID");
  }
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function iso(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new StepUpAuthenticationError("STEP_UP_TIME_INVALID");
  return date.toISOString();
}

export function createStepUpChallengeMaterial({
  tenantId,
  subjectId,
  action,
  factorId,
  now = new Date(),
  idFactory = randomUUID,
  bytesFactory = randomBytes,
} = {}) {
  if (!STEP_UP_POLICY.supportedActions.includes(action) || !FACTOR_ID.test(factorId ?? "")) {
    throw new StepUpAuthenticationError("STEP_UP_CHALLENGE_INVALID");
  }
  const issuedAt = new Date(iso(now));
  const expiresAt = new Date(issuedAt.getTime() + STEP_UP_POLICY.challengeLifetimeSeconds * 1000);
  const challengeId = `suc_${idFactory()}`;
  const sessionId = `sus_${idFactory()}`;
  const nonceBase64url = bytesFactory(32).toString("base64url");
  if (!CHALLENGE_ID.test(challengeId) || !SESSION_ID.test(sessionId) || !NONCE.test(nonceBase64url)) {
    throw new StepUpAuthenticationError("STEP_UP_RANDOMNESS_INVALID");
  }
  return Object.freeze({
    challengeId,
    factorId,
    algorithm: STEP_UP_POLICY.algorithm,
    tenantId,
    subjectId,
    action,
    nonceBase64url,
    sessionId,
    sessionIdHashSha256: hashStepUpValue(sessionId),
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  });
}

export function createStepUpSigningPayload(challenge) {
  if (!challenge || !CHALLENGE_ID.test(challenge.challengeId ?? "")
    || !FACTOR_ID.test(challenge.factorId ?? "")
    || !STEP_UP_POLICY.supportedActions.includes(challenge.action)
    || !NONCE.test(challenge.nonceBase64url ?? "")
    || !HASH.test(challenge.sessionIdHashSha256 ?? "")) {
    throw new StepUpAuthenticationError("STEP_UP_CHALLENGE_INVALID");
  }
  return Buffer.from(JSON.stringify({
    action: challenge.action,
    algorithm: STEP_UP_POLICY.algorithm,
    challengeId: challenge.challengeId,
    expiresAt: iso(challenge.expiresAt),
    factorId: challenge.factorId,
    issuedAt: iso(challenge.issuedAt),
    nonceBase64url: challenge.nonceBase64url,
    sessionIdHashSha256: challenge.sessionIdHashSha256,
    subjectId: challenge.subjectId,
    tenantId: challenge.tenantId,
  }), "utf8");
}

export function verifyStepUpChallengeSignature({ challenge, publicKeyBase64url, signatureBase64url } = {}) {
  if (!PUBLIC_KEY.test(publicKeyBase64url ?? "") || !SIGNATURE.test(signatureBase64url ?? "")) {
    throw new StepUpAuthenticationError("STEP_UP_SIGNATURE_INVALID");
  }
  const rawKey = Buffer.from(publicKeyBase64url, "base64url");
  const signature = Buffer.from(signatureBase64url, "base64url");
  if (rawKey.length !== 32 || signature.length !== 64) {
    throw new StepUpAuthenticationError("STEP_UP_SIGNATURE_INVALID");
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, rawKey]),
    format: "der",
    type: "spki",
  });
  if (!verify(null, createStepUpSigningPayload(challenge), publicKey, signature)) {
    throw new StepUpAuthenticationError("STEP_UP_SIGNATURE_INVALID");
  }
  return true;
}

export function createStepUpProofMaterial({ now = new Date(), idFactory = randomUUID } = {}) {
  const verifiedAt = new Date(iso(now));
  const proofId = `sup_${idFactory()}`;
  if (!PROOF_ID.test(proofId)) throw new StepUpAuthenticationError("STEP_UP_RANDOMNESS_INVALID");
  return Object.freeze({
    proofId,
    proofIdHashSha256: hashStepUpValue(proofId),
    verifiedAt: verifiedAt.toISOString(),
    expiresAt: new Date(verifiedAt.getTime() + STEP_UP_POLICY.proofLifetimeSeconds * 1000).toISOString(),
  });
}

export function normalizeStepUpPresentation(value) {
  if (value === null || value === undefined) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !PROOF_ID.test(value.proofId ?? "") || !SESSION_ID.test(value.sessionId ?? "")) {
    throw new StepUpAuthenticationError("STEP_UP_PRESENTATION_INVALID");
  }
  return Object.freeze({ proofId: value.proofId, sessionId: value.sessionId });
}
