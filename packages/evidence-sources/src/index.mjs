import { createHash, randomUUID } from "node:crypto";
import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const SOURCE_ID = /^src_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const KEY_ID = /^key_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const ENROLL_FIELDS = Object.freeze(["publicKeyBase64Url", "sourceId"]);
const ROTATE_FIELDS = ENROLL_FIELDS;
const REVOKE_FIELDS = Object.freeze(["keyId", "reasonCode", "sourceId"]);
const CONFIGURE_FIELDS = Object.freeze([
  "maximumInfluence",
  "rateLimitMaxEvents",
  "rateLimitSuspensionThreshold",
  "rateLimitWindowSeconds",
  "sourceId",
]);
const SUSPENSION_FIELDS = Object.freeze(["reasonCode", "sourceId"]);

export const EVIDENCE_SOURCE_REGISTRY_DENIAL = Object.freeze({
  statusCode: 403,
  code: "ACCESS_DENIED",
});

export class EvidenceSourceRegistryError extends Error {
  constructor(reasonCode) {
    super("Evidence source registry operation denied.");
    this.name = "EvidenceSourceRegistryError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new EvidenceSourceRegistryError(reasonCode);
}

function requireRecord(value, reasonCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) deny(reasonCode);
  return value;
}

function requireExactFields(value, fields, reasonCode) {
  const record = requireRecord(value, reasonCode);
  const keys = Object.keys(record).sort();
  if (keys.length !== fields.length || keys.some((key, index) => key !== fields[index])) deny(reasonCode);
  return record;
}

function requireAdminContext(context) {
  try {
    const trustedContext = assertNoTenantSwitch(context, []);
    if (!trustedContext.roles.includes("tenant-admin")) deny("TENANT_ADMIN_REQUIRED");
    return trustedContext;
  } catch (error) {
    if (error instanceof TenantContextError) deny("TENANT_CONTEXT_INVALID");
    throw error;
  }
}

function requireSourceId(sourceId) {
  if (!SOURCE_ID.test(sourceId ?? "")) deny("SOURCE_ID_INVALID");
  return sourceId;
}

function requireUtcNow(clock) {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) deny("REGISTRY_TIME_INVALID");
  return value.toISOString();
}

function createKeyId(idFactory) {
  const keyId = `key_${idFactory()}`;
  if (!KEY_ID.test(keyId)) deny("GENERATED_KEY_ID_INVALID");
  return keyId;
}

function decodePublicKey(publicKeyBase64Url) {
  if (!PUBLIC_KEY.test(publicKeyBase64Url ?? "")) deny("PUBLIC_KEY_INVALID");
  const bytes = Buffer.from(publicKeyBase64Url, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== publicKeyBase64Url) deny("PUBLIC_KEY_INVALID");
  return bytes;
}

export function fingerprintEd25519PublicKey(publicKeyBase64Url) {
  return createHash("sha256").update(decodePublicKey(publicKeyBase64Url)).digest("hex");
}

function normalizePublicKeyRequest(request, fields, reasonCode) {
  const input = requireExactFields(request, fields, reasonCode);
  return Object.freeze({
    sourceId: requireSourceId(input.sourceId),
    publicKeyBase64Url: input.publicKeyBase64Url,
    publicKeySha256: fingerprintEd25519PublicKey(input.publicKeyBase64Url),
  });
}

function validateMutationResult(result, expected) {
  if (!result
    || result.sourceId !== expected.sourceId
    || result.keyId !== expected.keyId
    || result.keySha256 !== expected.keySha256
    || result.sourceState !== expected.sourceState
    || !Number.isSafeInteger(result.keyVersion)
    || result.keyVersion < 1
    || !Number.isSafeInteger(result.sourceVersion)
    || result.sourceVersion < 2) {
    deny("REGISTRY_WRITE_UNCONFIRMED");
  }
  return Object.freeze({ ...result });
}

function validateRevocationResult(result, expected) {
  if (!result
    || result.sourceId !== expected.sourceId
    || result.keyId !== expected.keyId
    || result.keyState !== "revoked"
    || !["active", "suspended"].includes(result.sourceState)
    || !Number.isSafeInteger(result.keyVersion)
    || result.keyVersion < 1
    || !Number.isSafeInteger(result.sourceVersion)
    || result.sourceVersion < 2) {
    deny("REGISTRY_WRITE_UNCONFIRMED");
  }
  return Object.freeze({ ...result });
}

function requireIntegerInRange(value, minimum, maximum, reasonCode) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) deny(reasonCode);
  return value;
}

function normalizeSafeguardsRequest(request) {
  const input = requireExactFields(request, CONFIGURE_FIELDS, "SAFEGUARD_REQUEST_INVALID");
  if (typeof input.maximumInfluence !== "number"
    || !Number.isFinite(input.maximumInfluence)
    || input.maximumInfluence < 0.0001
    || input.maximumInfluence > 1) {
    deny("MAXIMUM_INFLUENCE_INVALID");
  }
  return Object.freeze({
    sourceId: requireSourceId(input.sourceId),
    rateLimitWindowSeconds: requireIntegerInRange(
      input.rateLimitWindowSeconds, 1, 3_600, "RATE_LIMIT_WINDOW_INVALID",
    ),
    rateLimitMaxEvents: requireIntegerInRange(
      input.rateLimitMaxEvents, 1, 100_000, "RATE_LIMIT_MAX_EVENTS_INVALID",
    ),
    rateLimitSuspensionThreshold: requireIntegerInRange(
      input.rateLimitSuspensionThreshold, 1, 1_000, "RATE_LIMIT_SUSPENSION_INVALID",
    ),
    maximumInfluence: input.maximumInfluence,
  });
}

function validateSafeguardsResult(result, expected) {
  if (!result
    || result.sourceId !== expected.sourceId
    || !["planned", "active", "suspended"].includes(result.sourceState)
    || !Number.isSafeInteger(result.sourceVersion)
    || result.sourceVersion < 2
    || result.rateLimitWindowSeconds !== expected.rateLimitWindowSeconds
    || result.rateLimitMaxEvents !== expected.rateLimitMaxEvents
    || result.rateLimitSuspensionThreshold !== expected.rateLimitSuspensionThreshold
    || result.maximumInfluence !== expected.maximumInfluence) {
    deny("REGISTRY_WRITE_UNCONFIRMED");
  }
  return Object.freeze({ ...result });
}

function validateSuspensionResult(result, sourceId, expectedState) {
  if (!result
    || result.sourceId !== sourceId
    || result.sourceState !== expectedState
    || !Number.isSafeInteger(result.sourceVersion)
    || result.sourceVersion < 2) {
    deny("REGISTRY_WRITE_UNCONFIRMED");
  }
  return Object.freeze({ ...result });
}

export function createEvidenceSourceRegistryService({
  enrollSource,
  rotateKey,
  revokeKey,
  configureSafeguards,
  setSuspension,
  idFactory = randomUUID,
  clock = () => new Date(),
} = {}) {
  if (typeof enrollSource !== "function"
    || typeof rotateKey !== "function"
    || typeof revokeKey !== "function"
    || typeof configureSafeguards !== "function"
    || typeof setSuspension !== "function") {
    throw new TypeError("Complete evidence source registry repositories are required.");
  }
  if (typeof idFactory !== "function" || typeof clock !== "function") {
    throw new TypeError("Evidence source registry ID and clock factories are required.");
  }

  return Object.freeze({
    async enroll({ context, request } = {}) {
      const trustedContext = requireAdminContext(context);
      const normalized = normalizePublicKeyRequest(request, ENROLL_FIELDS, "ENROLLMENT_REQUEST_INVALID");
      const keyId = createKeyId(idFactory);
      const result = await enrollSource({
        tenantId: trustedContext.tenantId,
        actorSubjectId: trustedContext.subjectId,
        sourceId: normalized.sourceId,
        keyId,
        publicKeyBase64Url: normalized.publicKeyBase64Url,
        publicKeySha256: normalized.publicKeySha256,
        occurredAt: requireUtcNow(clock),
      });
      return validateMutationResult(result, {
        sourceId: normalized.sourceId,
        keyId,
        keySha256: normalized.publicKeySha256,
        sourceState: "active",
      });
    },

    async rotate({ context, request } = {}) {
      const trustedContext = requireAdminContext(context);
      const normalized = normalizePublicKeyRequest(request, ROTATE_FIELDS, "ROTATION_REQUEST_INVALID");
      const keyId = createKeyId(idFactory);
      const result = await rotateKey({
        tenantId: trustedContext.tenantId,
        actorSubjectId: trustedContext.subjectId,
        sourceId: normalized.sourceId,
        keyId,
        publicKeyBase64Url: normalized.publicKeyBase64Url,
        publicKeySha256: normalized.publicKeySha256,
        occurredAt: requireUtcNow(clock),
      });
      return validateMutationResult(result, {
        sourceId: normalized.sourceId,
        keyId,
        keySha256: normalized.publicKeySha256,
        sourceState: "active",
      });
    },

    async revoke({ context, request } = {}) {
      const trustedContext = requireAdminContext(context);
      const input = requireExactFields(request, REVOKE_FIELDS, "REVOCATION_REQUEST_INVALID");
      requireSourceId(input.sourceId);
      if (!KEY_ID.test(input.keyId ?? "")) deny("KEY_ID_INVALID");
      if (!REASON_CODE.test(input.reasonCode ?? "")) deny("REVOCATION_REASON_INVALID");
      const result = await revokeKey({
        tenantId: trustedContext.tenantId,
        actorSubjectId: trustedContext.subjectId,
        sourceId: input.sourceId,
        keyId: input.keyId,
        reasonCode: input.reasonCode,
        occurredAt: requireUtcNow(clock),
      });
      return validateRevocationResult(result, input);
    },

    async configureSafeguards({ context, request } = {}) {
      const trustedContext = requireAdminContext(context);
      const normalized = normalizeSafeguardsRequest(request);
      const result = await configureSafeguards({
        tenantId: trustedContext.tenantId,
        actorSubjectId: trustedContext.subjectId,
        ...normalized,
        occurredAt: requireUtcNow(clock),
      });
      return validateSafeguardsResult(result, normalized);
    },

    async suspend({ context, request } = {}) {
      const trustedContext = requireAdminContext(context);
      const input = requireExactFields(request, SUSPENSION_FIELDS, "SUSPENSION_REQUEST_INVALID");
      requireSourceId(input.sourceId);
      if (!REASON_CODE.test(input.reasonCode ?? "")) deny("SUSPENSION_REASON_INVALID");
      const result = await setSuspension({
        tenantId: trustedContext.tenantId,
        actorSubjectId: trustedContext.subjectId,
        sourceId: input.sourceId,
        suspended: true,
        reasonCode: input.reasonCode,
        occurredAt: requireUtcNow(clock),
      });
      return validateSuspensionResult(result, input.sourceId, "suspended");
    },

    async resume({ context, request } = {}) {
      const trustedContext = requireAdminContext(context);
      const input = requireExactFields(request, SUSPENSION_FIELDS, "RESUMPTION_REQUEST_INVALID");
      requireSourceId(input.sourceId);
      if (!REASON_CODE.test(input.reasonCode ?? "")) deny("RESUMPTION_REASON_INVALID");
      const result = await setSuspension({
        tenantId: trustedContext.tenantId,
        actorSubjectId: trustedContext.subjectId,
        sourceId: input.sourceId,
        suspended: false,
        reasonCode: input.reasonCode,
        occurredAt: requireUtcNow(clock),
      });
      return validateSuspensionResult(result, input.sourceId, "active");
    },
  });
}

const ENROLL_SQL = `
SELECT enrolled_source_id, enrolled_key_id, enrolled_key_version,
       enrolled_key_sha256, enrolled_source_state, enrolled_source_version
FROM trust.enroll_evidence_source($1, $2, $3, $4)`;

const ROTATE_SQL = `
SELECT rotated_source_id, active_key_id, active_key_version,
       active_key_sha256, rotated_source_state, rotated_source_version
FROM trust.rotate_evidence_source_key($1, $2, $3, $4)`;

const REVOKE_SQL = `
SELECT revoked_source_id, revoked_key_id, revoked_key_version,
       revoked_key_state, resulting_source_state, resulting_source_version
FROM trust.revoke_evidence_source_key($1, $2, $3, $4)`;

const CONFIGURE_SAFEGUARDS_SQL = `
SELECT configured_source_id, configured_source_state, configured_source_version,
       rate_limit_window_seconds, rate_limit_max_events,
       rate_limit_suspension_threshold, maximum_influence
FROM trust.configure_evidence_source_safeguards($1, $2, $3, $4, $5, $6)`;

const SET_SUSPENSION_SQL = `
SELECT controlled_source_id, controlled_source_state, controlled_source_version
FROM trust.set_evidence_source_suspension($1, $2, $3, $4)`;

function requireSingleRow(result) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) deny("REGISTRY_WRITE_UNCONFIRMED");
  return result.rows[0];
}

export function createPostgresEvidenceSourceRegistryRepository({ query } = {}) {
  if (typeof query !== "function") throw new TypeError("A transaction-bound PostgreSQL query function is required.");
  return Object.freeze({
    async enrollSource(record, { signal } = {}) {
      const row = requireSingleRow(await query(ENROLL_SQL, [
        record.sourceId,
        record.keyId,
        record.publicKeyBase64Url,
        record.occurredAt,
      ], { signal }));
      return {
        sourceId: row.enrolled_source_id,
        keyId: row.enrolled_key_id,
        keyVersion: Number(row.enrolled_key_version),
        keySha256: row.enrolled_key_sha256,
        sourceState: row.enrolled_source_state,
        sourceVersion: Number(row.enrolled_source_version),
      };
    },
    async rotateKey(record, { signal } = {}) {
      const row = requireSingleRow(await query(ROTATE_SQL, [
        record.sourceId,
        record.keyId,
        record.publicKeyBase64Url,
        record.occurredAt,
      ], { signal }));
      return {
        sourceId: row.rotated_source_id,
        keyId: row.active_key_id,
        keyVersion: Number(row.active_key_version),
        keySha256: row.active_key_sha256,
        sourceState: row.rotated_source_state,
        sourceVersion: Number(row.rotated_source_version),
      };
    },
    async revokeKey(record, { signal } = {}) {
      const row = requireSingleRow(await query(REVOKE_SQL, [
        record.sourceId,
        record.keyId,
        record.reasonCode,
        record.occurredAt,
      ], { signal }));
      return {
        sourceId: row.revoked_source_id,
        keyId: row.revoked_key_id,
        keyVersion: Number(row.revoked_key_version),
        keyState: row.revoked_key_state,
        sourceState: row.resulting_source_state,
        sourceVersion: Number(row.resulting_source_version),
      };
    },
    async configureSafeguards(record, { signal } = {}) {
      const row = requireSingleRow(await query(CONFIGURE_SAFEGUARDS_SQL, [
        record.sourceId,
        record.rateLimitWindowSeconds,
        record.rateLimitMaxEvents,
        record.rateLimitSuspensionThreshold,
        record.maximumInfluence,
        record.occurredAt,
      ], { signal }));
      return {
        sourceId: row.configured_source_id,
        sourceState: row.configured_source_state,
        sourceVersion: Number(row.configured_source_version),
        rateLimitWindowSeconds: Number(row.rate_limit_window_seconds),
        rateLimitMaxEvents: Number(row.rate_limit_max_events),
        rateLimitSuspensionThreshold: Number(row.rate_limit_suspension_threshold),
        maximumInfluence: Number(row.maximum_influence),
      };
    },
    async setSuspension(record, { signal } = {}) {
      const row = requireSingleRow(await query(SET_SUSPENSION_SQL, [
        record.sourceId,
        record.suspended,
        record.reasonCode,
        record.occurredAt,
      ], { signal }));
      return {
        sourceId: row.controlled_source_id,
        sourceState: row.controlled_source_state,
        sourceVersion: Number(row.controlled_source_version),
      };
    },
  });
}

export function evidenceSourceRegistrySafeDenial(error) {
  if (!(error instanceof EvidenceSourceRegistryError)) throw error;
  return EVIDENCE_SOURCE_REGISTRY_DENIAL;
}
