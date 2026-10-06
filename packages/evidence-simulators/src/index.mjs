import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
} from "node:crypto";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SOURCE_ID = /^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const KEY_ID = /^key_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_TYPES = Object.freeze(["identity", "device", "behaviour", "certificate", "compliance"]);
const EVIDENCE_TYPE_SET = new Set(EVIDENCE_TYPES);
const DEFAULT_OBSERVED_AT = "2026-10-05T08:00:00.000Z";
const PKCS8_ED25519_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const GENERATOR = "tenant-trust-deterministic-demo-v1";
const ADVERSARIAL_GENERATOR = "tenant-trust-deterministic-adversarial-v1";

export const ADVERSARIAL_EVIDENCE_SCENARIO_IDS = Object.freeze([
  "forged-signature",
  "revoked-source",
  "mixed-tenants",
  "missing-signals",
  "duplicate-event-id",
  "event-flood",
]);

const CATALOG = Object.freeze({
  alpha: Object.freeze({
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
    defaultSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
    sources: Object.freeze([
      Object.freeze({ evidenceType: "identity", sourceId: "src_018f1234-5678-7abc-8def-0123456789b6", maximumAgeSeconds: 300 }),
      Object.freeze({ evidenceType: "device", sourceId: "src_018f1234-5678-7abc-8def-0123456789b7", maximumAgeSeconds: 300 }),
      Object.freeze({ evidenceType: "behaviour", sourceId: "src_018f1234-5678-7abc-8def-0123456789b8", maximumAgeSeconds: 300 }),
      Object.freeze({ evidenceType: "certificate", sourceId: "src_018f1234-5678-7abc-8def-0123456789b9", maximumAgeSeconds: 60 }),
      Object.freeze({ evidenceType: "compliance", sourceId: "src_018f1234-5678-7abc-8def-0123456789ba", maximumAgeSeconds: 3600 }),
    ]),
  }),
  beta: Object.freeze({
    tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac",
    defaultSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
    sources: Object.freeze([
      Object.freeze({ evidenceType: "identity", sourceId: "src_018f1234-5678-7abc-8def-0123456789bb", maximumAgeSeconds: 300 }),
      Object.freeze({ evidenceType: "device", sourceId: "src_018f1234-5678-7abc-8def-0123456789bc", maximumAgeSeconds: 300 }),
      Object.freeze({ evidenceType: "behaviour", sourceId: "src_018f1234-5678-7abc-8def-0123456789bd", maximumAgeSeconds: 300 }),
      Object.freeze({ evidenceType: "certificate", sourceId: "src_018f1234-5678-7abc-8def-0123456789be", maximumAgeSeconds: 60 }),
      Object.freeze({ evidenceType: "compliance", sourceId: "src_018f1234-5678-7abc-8def-0123456789bf", maximumAgeSeconds: 3600 }),
    ]),
  }),
});

export const DEMO_EVIDENCE_SOURCE_CATALOG = CATALOG;

export class EvidenceSimulatorError extends Error {
  constructor(reasonCode) {
    super("Deterministic evidence simulation failed.");
    this.name = "EvidenceSimulatorError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new EvidenceSimulatorError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (value && typeof value === "object"
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`).join(",")}}`;
  }
  fail("CANONICAL_CONTENT_INVALID");
}

export function canonicalizeEvidenceJson(value) {
  return canonicalValue(value);
}

function hashParts(label, ...parts) {
  const hash = createHash("sha256");
  for (const part of [label, ...parts]) {
    const bytes = Buffer.from(part, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest();
}

function uuidFromDigest(digest) {
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function requireUtc(value) {
  if (typeof value !== "string" || !value.endsWith("Z")) fail("OBSERVATION_TIME_INVALID");
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail("OBSERVATION_TIME_INVALID");
  return date;
}

function requireSequence(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail("SOURCE_SEQUENCE_INVALID");
  return value;
}

function provenance() {
  return { generator: GENERATOR, synthetic: true };
}

function payloadFor(evidenceType) {
  switch (evidenceType) {
    case "identity":
      return {
        authenticationAssurance: "aal2",
        directoryState: "active",
        factors: ["password", "totp"],
        provenance: provenance(),
      };
    case "device":
      return {
        deviceRisk: "low",
        posture: {
          diskEncryption: "enabled",
          managed: true,
          patchAgeDays: 2,
          screenLock: "enabled",
          synthetic: true,
        },
        provenance: provenance(),
      };
    case "behaviour":
      return {
        activity: {
          failedLoginCount: 0,
          impossibleTravel: false,
          newCountry: false,
        },
        provenance: provenance(),
        riskBand: "low",
      };
    case "certificate":
      return {
        certificateState: "active",
        daysUntilExpiry: 30,
        provenance: provenance(),
        statusSource: "application-inventory",
      };
    case "compliance":
      return {
        attestation: {
          controlsEvaluated: 12,
          controlsPassed: 12,
          framework: "tenant-trust-demo-v1",
          status: "compliant",
          synthetic: true,
        },
        provenance: provenance(),
      };
    default:
      fail("EVIDENCE_TYPE_INVALID");
  }
}

function keyMaterial(tenantId, sourceId) {
  const seed = hashParts("tenant-trust-evidence-simulator-key-v1", tenantId, sourceId);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (publicJwk.kty !== "OKP" || publicJwk.crv !== "Ed25519" || typeof publicJwk.x !== "string") {
    fail("SIMULATOR_KEY_INVALID");
  }
  const publicBytes = Buffer.from(publicJwk.x, "base64url");
  if (publicBytes.length !== 32 || publicBytes.toString("base64url") !== publicJwk.x) fail("SIMULATOR_KEY_INVALID");
  const fingerprint = createHash("sha256").update(publicBytes).digest("hex");
  const keyId = `key_${uuidFromDigest(hashParts("tenant-trust-evidence-simulator-key-id-v1", tenantId, sourceId, fingerprint))}`;
  if (!KEY_ID.test(keyId)) fail("SIMULATOR_KEY_INVALID");
  return { privateKey, publicKeyBase64Url: publicJwk.x, publicKeySha256: fingerprint, keyId };
}

function validateSimulatorConfiguration({ tenantId, sourceId, evidenceType, maximumAgeSeconds }) {
  if (!TENANT_ID.test(tenantId ?? "")
    || !SOURCE_ID.test(sourceId ?? "")
    || !EVIDENCE_TYPE_SET.has(evidenceType)
    || !Number.isSafeInteger(maximumAgeSeconds)
    || maximumAgeSeconds < 1
    || maximumAgeSeconds > 86_400) {
    fail("SIMULATOR_CONFIGURATION_INVALID");
  }
}

function signUnsignedEnvelope(unsigned, material) {
  const content = Buffer.from(canonicalizeEvidenceJson(unsigned), "utf8");
  const signedContentSha256 = createHash("sha256").update(content).digest("hex");
  const signature = signEd25519(null, content, material.privateKey);
  if (signature.length !== 64) fail("SIMULATOR_SIGNATURE_INVALID");
  return deepFreeze({
    ...unsigned,
    signature: {
      algorithm: "Ed25519",
      canonicalization: "tenant-trust-evidence-json-v1",
      keyId: material.keyId,
      signedContentSha256,
      signatureBase64Url: signature.toString("base64url"),
    },
  });
}

function sourceFor(tenantAlias, evidenceType) {
  const tenant = CATALOG[tenantAlias];
  if (!tenant) fail("TENANT_ALIAS_INVALID");
  const source = tenant.sources.find((candidate) => candidate.evidenceType === evidenceType);
  if (!source) fail("EVIDENCE_TYPE_INVALID");
  return { tenant, source };
}

function simulatorFor(tenantAlias, evidenceType) {
  const { tenant, source } = sourceFor(tenantAlias, evidenceType);
  return createDeterministicEvidenceSimulator({ tenantId: tenant.tenantId, ...source });
}

function addMilliseconds(utc, milliseconds) {
  const date = requireUtc(utc);
  const result = new Date(date.getTime() + milliseconds);
  if (!Number.isFinite(result.getTime())) fail("OBSERVATION_TIME_INVALID");
  return result.toISOString();
}

function resignEnvelope(envelope, material, overrides = {}) {
  const unsigned = { ...unsignedEvidenceEnvelope(envelope), ...overrides };
  return signUnsignedEnvelope(unsigned, material);
}

export function unsignedEvidenceEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) fail("EVIDENCE_ENVELOPE_INVALID");
  const { signature, ...unsigned } = envelope;
  if (!signature) fail("EVIDENCE_ENVELOPE_INVALID");
  return unsigned;
}

export function createDeterministicEvidenceSimulator(configuration = {}) {
  validateSimulatorConfiguration(configuration);
  const { tenantId, sourceId, evidenceType, maximumAgeSeconds } = configuration;
  const material = keyMaterial(tenantId, sourceId);
  const enrollment = deepFreeze({
    tenantId,
    sourceId,
    evidenceType,
    algorithm: "Ed25519",
    keyId: material.keyId,
    publicKeyBase64Url: material.publicKeyBase64Url,
    publicKeySha256: material.publicKeySha256,
    synthetic: true,
  });

  return Object.freeze({
    evidenceType,
    enrollment,
    generate({ subjectId, sourceSequence, observedAt } = {}) {
      if (!SUBJECT_ID.test(subjectId ?? "")) fail("SUBJECT_ID_INVALID");
      const sequence = requireSequence(sourceSequence);
      const observed = requireUtc(observedAt);
      const expires = new Date(observed.getTime() + maximumAgeSeconds * 1_000);
      if (!Number.isFinite(expires.getTime())) fail("OBSERVATION_TIME_INVALID");
      const payload = payloadFor(evidenceType);
      const identityBytes = canonicalizeEvidenceJson({
        tenantId,
        subjectId,
        sourceId,
        evidenceType,
        observedAt,
        expiresAt: expires.toISOString(),
        sourceSequence: sequence,
        payload,
      });
      const eventId = `evt_${uuidFromDigest(hashParts("tenant-trust-evidence-simulator-event-v1", identityBytes))}`;
      const nonce = hashParts("tenant-trust-evidence-simulator-nonce-v1", identityBytes).subarray(0, 18).toString("base64url");
      if (!EVENT_ID.test(eventId)) fail("SIMULATOR_EVENT_ID_INVALID");

      const unsigned = {
        schemaVersion: "1.0.0",
        eventId,
        tenantId,
        subjectId,
        sourceId,
        evidenceType,
        observedAt,
        expiresAt: expires.toISOString(),
        sourceSequence: sequence,
        nonce,
        synthetic: true,
        payload,
      };
      return signUnsignedEnvelope(unsigned, material);
    },
  });
}

export function generateDeterministicDemoEvidenceSet({
  tenantAlias = "alpha",
  subjectId,
  observedAt = DEFAULT_OBSERVED_AT,
  sourceSequence = 1,
} = {}) {
  const tenant = CATALOG[tenantAlias];
  if (!tenant) fail("TENANT_ALIAS_INVALID");
  const selectedSubjectId = subjectId ?? tenant.defaultSubjectId;
  if (!SUBJECT_ID.test(selectedSubjectId ?? "")) fail("SUBJECT_ID_INVALID");
  requireUtc(observedAt);
  requireSequence(sourceSequence);

  const simulators = tenant.sources.map((source) => createDeterministicEvidenceSimulator({
    tenantId: tenant.tenantId,
    ...source,
  }));
  return deepFreeze({
    fixtureVersion: "1.0.0",
    generator: GENERATOR,
    tenantAlias,
    tenantId: tenant.tenantId,
    subjectId: selectedSubjectId,
    observedAt,
    sourceSequence,
    enrollments: simulators.map((simulator) => simulator.enrollment),
    envelopes: simulators.map((simulator) => simulator.generate({
      subjectId: selectedSubjectId,
      sourceSequence,
      observedAt,
    })),
  });
}

export function generateAdversarialEvidenceFixtureSet({
  tenantAlias = "alpha",
  subjectId,
  observedAt = DEFAULT_OBSERVED_AT,
  sourceSequence = 100,
  floodEventCount = 7,
} = {}) {
  const tenant = CATALOG[tenantAlias];
  if (!tenant) fail("TENANT_ALIAS_INVALID");
  const selectedSubjectId = subjectId ?? tenant.defaultSubjectId;
  if (!SUBJECT_ID.test(selectedSubjectId ?? "")) fail("SUBJECT_ID_INVALID");
  requireUtc(observedAt);
  requireSequence(sourceSequence);
  if (sourceSequence > 9_007_199_254_739_000) fail("SOURCE_SEQUENCE_INVALID");
  if (!Number.isSafeInteger(floodEventCount) || floodEventCount < 7 || floodEventCount > 1_000) {
    fail("FLOOD_EVENT_COUNT_INVALID");
  }

  const otherAlias = tenantAlias === "alpha" ? "beta" : "alpha";
  const otherTenant = CATALOG[otherAlias];
  const identity = simulatorFor(tenantAlias, "identity");
  const device = simulatorFor(tenantAlias, "device");
  const behaviour = simulatorFor(tenantAlias, "behaviour");
  const certificate = simulatorFor(tenantAlias, "certificate");
  const compliance = simulatorFor(tenantAlias, "compliance");

  const forgedBase = identity.generate({
    subjectId: selectedSubjectId,
    sourceSequence,
    observedAt,
  });
  const foreignIdentitySource = sourceFor(otherAlias, "identity").source;
  const foreignMaterial = keyMaterial(otherTenant.tenantId, foreignIdentitySource.sourceId);
  const forgedContent = Buffer.from(canonicalizeEvidenceJson(unsignedEvidenceEnvelope(forgedBase)), "utf8");
  const forgedSignature = signEd25519(null, forgedContent, foreignMaterial.privateKey).toString("base64url");
  const forgedEnvelope = deepFreeze({
    ...forgedBase,
    signature: { ...forgedBase.signature, signatureBase64Url: forgedSignature },
  });

  const revokedEnvelope = device.generate({
    subjectId: selectedSubjectId,
    sourceSequence: sourceSequence + 1,
    observedAt: addMilliseconds(observedAt, 1),
  });

  const mixedBase = behaviour.generate({
    subjectId: selectedSubjectId,
    sourceSequence: sourceSequence + 2,
    observedAt: addMilliseconds(observedAt, 2),
  });
  const behaviourMaterial = keyMaterial(tenant.tenantId, behaviour.enrollment.sourceId);
  const mixedEnvelope = resignEnvelope(mixedBase, behaviourMaterial, {
    tenantId: otherTenant.tenantId,
    subjectId: otherTenant.defaultSubjectId,
    eventId: `evt_${uuidFromDigest(hashParts("tenant-trust-adversarial-mixed-event-v1", tenantAlias, observedAt))}`,
    nonce: hashParts("tenant-trust-adversarial-mixed-nonce-v1", tenantAlias, observedAt).subarray(0, 18).toString("base64url"),
  });

  const missingSignalEnvelopes = [identity, device, certificate].map((simulator, index) => simulator.generate({
    subjectId: selectedSubjectId,
    sourceSequence: sourceSequence + 10 + index,
    observedAt: addMilliseconds(observedAt, 10 + index),
  }));
  const missingSignalEnrollments = [identity.enrollment, device.enrollment, certificate.enrollment];

  const duplicateFirst = compliance.generate({
    subjectId: selectedSubjectId,
    sourceSequence: sourceSequence + 20,
    observedAt: addMilliseconds(observedAt, 20),
  });
  const duplicateOriginalSecond = compliance.generate({
    subjectId: selectedSubjectId,
    sourceSequence: sourceSequence + 21,
    observedAt: addMilliseconds(observedAt, 21),
  });
  const complianceMaterial = keyMaterial(tenant.tenantId, compliance.enrollment.sourceId);
  const duplicateSecond = resignEnvelope(duplicateOriginalSecond, complianceMaterial, {
    eventId: duplicateFirst.eventId,
  });

  const floodEnvelopes = Array.from({ length: floodEventCount }, (_, index) => behaviour.generate({
    subjectId: selectedSubjectId,
    sourceSequence: sourceSequence + 100 + index,
    observedAt: addMilliseconds(observedAt, 100 + index),
  }));

  return deepFreeze({
    fixtureVersion: "1.0.0",
    generator: ADVERSARIAL_GENERATOR,
    tenantAlias,
    tenantId: tenant.tenantId,
    subjectId: selectedSubjectId,
    observedAt,
    scenarios: [
      {
        id: "forged-signature",
        attackClass: "source-authentication",
        enrollments: [identity.enrollment],
        envelopes: [forgedEnvelope],
        expectedOutcome: { decision: "reject", reasonCode: "EVIDENCE_SIGNATURE_INVALID" },
      },
      {
        id: "revoked-source",
        attackClass: "revoked-authority",
        enrollments: [device.enrollment],
        envelopes: [revokedEnvelope],
        authority: { sourceState: "suspended", keyState: "revoked" },
        expectedOutcome: { decision: "reject", reasonCode: "VERIFICATION_CONTEXT_NOT_FOUND" },
      },
      {
        id: "mixed-tenants",
        attackClass: "tenant-binding",
        enrollments: [behaviour.enrollment],
        envelopes: [mixedEnvelope],
        authority: { registeredTenantId: tenant.tenantId, presentedTenantId: otherTenant.tenantId },
        expectedOutcome: { decision: "reject", reasonCode: "VERIFICATION_CONTEXT_NOT_FOUND" },
      },
      {
        id: "missing-signals",
        attackClass: "evidence-completeness",
        enrollments: missingSignalEnrollments,
        envelopes: missingSignalEnvelopes,
        requiredEvidenceTypes: [...EVIDENCE_TYPES],
        missingEvidenceTypes: ["behaviour", "compliance"],
        expectedOutcome: { decision: "withhold", reasonCode: "REQUIRED_EVIDENCE_MISSING" },
      },
      {
        id: "duplicate-event-id",
        attackClass: "replay",
        enrollments: [compliance.enrollment],
        envelopes: [duplicateFirst, duplicateSecond],
        expectedOutcomes: [
          { decision: "accept", reasonCode: null },
          { decision: "reject", reasonCode: "EVIDENCE_EVENT_REPLAYED" },
        ],
      },
      {
        id: "event-flood",
        attackClass: "source-flood",
        enrollments: [behaviour.enrollment],
        envelopes: floodEnvelopes,
        safeguards: {
          rateLimitWindowSeconds: 60,
          rateLimitMaxEvents: 4,
          rateLimitSuspensionThreshold: 2,
          maximumInfluence: 0.4,
          tenantMaximumSourceInfluence: 0.2,
        },
        expectedSummary: {
          acceptedCount: 4,
          rateLimitedCount: 2,
          finalReasonCode: "VERIFICATION_CONTEXT_NOT_FOUND",
          sourceSuspended: true,
          maximumSourceInfluence: 0.2,
        },
      },
    ],
  });
}
