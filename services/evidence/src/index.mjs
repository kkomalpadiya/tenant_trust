import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
} from "node:crypto";
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const COMMON_SCHEMA_URL = new URL(
  "../../../packages/contracts/schemas/common.schema.json",
  import.meta.url,
);
const ENVELOPE_SCHEMA_URL = new URL(
  "../../../packages/contracts/schemas/evidence/signed-evidence-envelope.schema.json",
  import.meta.url,
);
const commonSchema = JSON.parse(readFileSync(COMMON_SCHEMA_URL, "utf8"));
const envelopeSchema = JSON.parse(readFileSync(ENVELOPE_SCHEMA_URL, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(commonSchema);
const validateEnvelope = ajv.compile(envelopeSchema);

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SOURCE_ID = /^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const KEY_ID = /^key_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const EVIDENCE_TYPES = new Set(["identity", "device", "behaviour", "certificate", "compliance"]);
const evidenceIngestionServiceBrand = new WeakSet();
const RESOLUTION_SQL = `
SELECT tenant_id, subject_id, source_id, evidence_type, source_synthetic,
       maximum_age_seconds, source_state, verification_algorithm,
       key_id, key_state, key_version, public_key_base64url,
       public_key_sha256, key_enrolled_at
FROM trust.resolve_evidence_verification_context($1, $2, $3, $4)`;

export const EVIDENCE_INGESTION_POLICY = Object.freeze({
  schemaVersion: "1.0.0",
  endpoint: "/v1/evidence",
  maximumEnvelopeBytes: 65_536,
  maximumPayloadBytes: 32_768,
  signatureAlgorithm: "Ed25519",
  canonicalizationProfile: "tenant-trust-evidence-json-v1",
  acceptedSourceState: "active",
  acceptedKeyState: "active",
  rawPayloadPersistence: false,
});

export const SIGNED_EVIDENCE_CONTRACT_SCHEMAS = Object.freeze({
  common: commonSchema,
  envelope: envelopeSchema,
});

export class EvidenceRejectedError extends Error {
  constructor(reasonCode) {
    super("Evidence was rejected.");
    this.name = "EvidenceRejectedError";
    this.reasonCode = reasonCode;
  }
}

export class EvidenceIngestionUnavailableError extends Error {
  constructor() {
    super("Evidence ingestion is unavailable.");
    this.name = "EvidenceIngestionUnavailableError";
  }
}

function reject(reasonCode) {
  throw new EvidenceRejectedError(reasonCode);
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) reject("EVIDENCE_SCHEMA_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`)
      .join(",")}}`;
  }
  reject("EVIDENCE_SCHEMA_INVALID");
}

export function canonicalizeEvidenceJson(value) {
  return canonicalValue(value);
}

export function unsignedEvidenceEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    reject("EVIDENCE_SCHEMA_INVALID");
  }
  const { signature, ...unsigned } = envelope;
  if (!signature) reject("EVIDENCE_SCHEMA_INVALID");
  return unsigned;
}

function canonicalByteLength(value) {
  return Buffer.byteLength(canonicalizeEvidenceJson(value), "utf8");
}

function decodeCanonicalBase64Url(value, expectedBytes, reasonCode) {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== expectedBytes || bytes.toString("base64url") !== value) reject(reasonCode);
  return bytes;
}

function safeDigestEqual(leftHex, rightHex) {
  if (!SHA256.test(leftHex ?? "") || !SHA256.test(rightHex ?? "")) return false;
  return timingSafeEqual(Buffer.from(leftHex, "hex"), Buffer.from(rightHex, "hex"));
}

function assertVerificationContext(context, envelope) {
  if (!context
    || !TENANT_ID.test(context.tenantId ?? "")
    || !SUBJECT_ID.test(context.subjectId ?? "")
    || !SOURCE_ID.test(context.sourceId ?? "")
    || !KEY_ID.test(context.keyId ?? "")
    || !EVIDENCE_TYPES.has(context.evidenceType)
    || typeof context.sourceSynthetic !== "boolean"
    || context.sourceState !== EVIDENCE_INGESTION_POLICY.acceptedSourceState
    || context.keyState !== EVIDENCE_INGESTION_POLICY.acceptedKeyState
    || context.verificationAlgorithm !== "Ed25519"
    || !Number.isSafeInteger(context.keyVersion)
    || context.keyVersion < 1
    || !Number.isSafeInteger(context.maximumAgeSeconds)
    || context.maximumAgeSeconds < 1
    || context.maximumAgeSeconds > 86_400
    || !PUBLIC_KEY.test(context.publicKeyBase64Url ?? "")
    || !SHA256.test(context.publicKeySha256 ?? "")) {
    reject("VERIFICATION_CONTEXT_INVALID");
  }
  if (context.tenantId !== envelope.tenantId
    || context.subjectId !== envelope.subjectId
    || context.sourceId !== envelope.sourceId
    || context.keyId !== envelope.signature.keyId
    || context.evidenceType !== envelope.evidenceType
    || context.sourceSynthetic !== envelope.synthetic) {
    reject("EVIDENCE_BINDING_INVALID");
  }
}

function verifyEnvelopeSignature(envelope, context) {
  const publicKeyBytes = decodeCanonicalBase64Url(
    context.publicKeyBase64Url,
    32,
    "VERIFICATION_KEY_INVALID",
  );
  const publicKeySha256 = createHash("sha256").update(publicKeyBytes).digest("hex");
  if (!safeDigestEqual(publicKeySha256, context.publicKeySha256)) {
    reject("VERIFICATION_KEY_INVALID");
  }

  const canonicalBytes = Buffer.from(
    canonicalizeEvidenceJson(unsignedEvidenceEnvelope(envelope)),
    "utf8",
  );
  const contentHashSha256 = createHash("sha256").update(canonicalBytes).digest("hex");
  if (!safeDigestEqual(contentHashSha256, envelope.signature.signedContentSha256)) {
    reject("SIGNED_CONTENT_DIGEST_INVALID");
  }
  const signature = decodeCanonicalBase64Url(
    envelope.signature.signatureBase64Url,
    64,
    "EVIDENCE_SIGNATURE_INVALID",
  );
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: context.publicKeyBase64Url },
    format: "jwk",
  });
  if (!verifyEd25519(null, canonicalBytes, publicKey, signature)) {
    reject("EVIDENCE_SIGNATURE_INVALID");
  }
  return contentHashSha256;
}

export function createEvidenceIngestionService({ resolveVerificationContext } = {}) {
  if (typeof resolveVerificationContext !== "function") {
    throw new TypeError("An evidence verification-context resolver is required.");
  }

  const service = Object.freeze({
    policy: EVIDENCE_INGESTION_POLICY,
    async ingest({ envelope, encodedByteLength, signal } = {}) {
      if (!validateEnvelope(envelope)) reject("EVIDENCE_SCHEMA_INVALID");
      const measuredEnvelopeBytes = encodedByteLength ?? canonicalByteLength(envelope);
      if (!Number.isSafeInteger(measuredEnvelopeBytes) || measuredEnvelopeBytes < 1) {
        reject("EVIDENCE_SIZE_INVALID");
      }
      if (measuredEnvelopeBytes > EVIDENCE_INGESTION_POLICY.maximumEnvelopeBytes
        || canonicalByteLength(envelope.payload) > EVIDENCE_INGESTION_POLICY.maximumPayloadBytes) {
        reject("EVIDENCE_TOO_LARGE");
      }

      const context = await resolveVerificationContext({
        tenantId: envelope.tenantId,
        subjectId: envelope.subjectId,
        sourceId: envelope.sourceId,
        keyId: envelope.signature.keyId,
      }, { signal });
      if (context === null) reject("VERIFICATION_CONTEXT_NOT_FOUND");
      assertVerificationContext(context, envelope);
      const contentHashSha256 = verifyEnvelopeSignature(envelope, context);

      return Object.freeze({
        status: "accepted",
        eventId: envelope.eventId,
        tenantId: envelope.tenantId,
        subjectId: envelope.subjectId,
        sourceId: envelope.sourceId,
        evidenceType: envelope.evidenceType,
        sourceSequence: envelope.sourceSequence,
        synthetic: envelope.synthetic,
        contentHashSha256,
      });
    },
  });
  evidenceIngestionServiceBrand.add(service);
  return service;
}

export function assertEvidenceIngestionService(service) {
  if (!service
    || !evidenceIngestionServiceBrand.has(service)
    || typeof service.ingest !== "function"
    || service.policy !== EVIDENCE_INGESTION_POLICY) {
    throw new TypeError("A branded evidence ingestion service is required.");
  }
  return service;
}

function requireBinding(binding) {
  if (!binding
    || !TENANT_ID.test(binding.tenantId ?? "")
    || !SUBJECT_ID.test(binding.subjectId ?? "")
    || !SOURCE_ID.test(binding.sourceId ?? "")
    || !KEY_ID.test(binding.keyId ?? "")) {
    throw new EvidenceIngestionUnavailableError();
  }
}

function asIsoTimestamp(value) {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) throw new EvidenceIngestionUnavailableError();
  return timestamp.toISOString();
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original error remains authoritative.
  }
}

export function createPostgresEvidenceVerificationResolver({ pool } = {}) {
  if (!pool || typeof pool.connect !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }
  return async function resolveVerificationContext(binding, { signal } = {}) {
    requireBinding(binding);
    if (signal?.aborted) throw new EvidenceIngestionUnavailableError();
    const client = await pool.connect();
    let transactionStarted = false;
    try {
      const query = (text, values = []) => {
        if (signal?.aborted) throw new EvidenceIngestionUnavailableError();
        return client.query({ text, values, signal });
      };
      await query("BEGIN");
      transactionStarted = true;
      await query("SET LOCAL ROLE tenant_trust_app");
      await query(
        `SELECT
           set_config('statement_timeout', $1, true),
           set_config('lock_timeout', $2, true),
           set_config('idle_in_transaction_session_timeout', $3, true)`,
        ["4000ms", "1000ms", "5000ms"],
      );
      const result = await query(RESOLUTION_SQL, [
        binding.tenantId,
        binding.subjectId,
        binding.sourceId,
        binding.keyId,
      ]);
      if (result.rowCount > 1) throw new EvidenceIngestionUnavailableError();
      const context = result.rowCount === 0 ? null : Object.freeze({
        tenantId: result.rows[0].tenant_id,
        subjectId: result.rows[0].subject_id,
        sourceId: result.rows[0].source_id,
        evidenceType: result.rows[0].evidence_type,
        sourceSynthetic: result.rows[0].source_synthetic,
        maximumAgeSeconds: Number(result.rows[0].maximum_age_seconds),
        sourceState: result.rows[0].source_state,
        verificationAlgorithm: result.rows[0].verification_algorithm,
        keyId: result.rows[0].key_id,
        keyState: result.rows[0].key_state,
        keyVersion: Number(result.rows[0].key_version),
        publicKeyBase64Url: result.rows[0].public_key_base64url,
        publicKeySha256: result.rows[0].public_key_sha256,
        keyEnrolledAt: asIsoTimestamp(result.rows[0].key_enrolled_at),
      });
      await query("COMMIT");
      return context;
    } catch (error) {
      if (transactionStarted) await rollbackQuietly(client);
      if (error instanceof EvidenceIngestionUnavailableError) throw error;
      throw new EvidenceIngestionUnavailableError();
    } finally {
      client.release();
    }
  };
}
