import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";
import {
  TrustModelDefinitionError,
  defineTrustModelConfiguration,
} from "@tenant-trust/trust-model";
import {
  TrustSmoothingError,
  defineTemporalTrustConfiguration,
} from "./temporal-smoothing.mjs";

const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CONFIGURATION_STATES = new Set(["draft", "active", "superseded"]);
const EVENT_TYPES = new Set(["draft_created", "activated", "rollback_activated"]);
const DRAFT_FIELDS = Object.freeze([
  "initialScore",
  "maximumSourceInfluence",
  "modelVersion",
  "reasonCode",
  "smoothingAlpha",
  "staleAfterSeconds",
  "weights",
]);
const ACTIVATE_FIELDS = Object.freeze(["configurationVersion", "reasonCode"]);
const ROLLBACK_FIELDS = Object.freeze(["reasonCode", "targetConfigurationVersion"]);

const CREATE_DRAFT_SQL = `
  SELECT * FROM trust.create_trust_configuration_draft(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
  )
`;
const ACTIVATE_SQL = "SELECT * FROM trust.activate_trust_configuration($1, $2, $3)";
const ROLLBACK_SQL = "SELECT * FROM trust.rollback_trust_configuration($1, $2, $3)";
const HISTORY_SQL = "SELECT * FROM trust.list_trust_configuration_history()";

export const TRUST_CONFIGURATION_MANAGEMENT_DENIAL = Object.freeze({
  statusCode: 403,
  code: "ACCESS_DENIED",
});

export class TrustConfigurationManagementError extends Error {
  constructor(reasonCode) {
    super("Trust configuration management operation denied.");
    this.name = "TrustConfigurationManagementError";
    this.reasonCode = reasonCode;
  }
}

function deny(reasonCode) {
  throw new TrustConfigurationManagementError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function requireRecord(value, reasonCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) deny(reasonCode);
  return value;
}

function requireExactFields(value, fields, reasonCode) {
  const record = requireRecord(value, reasonCode);
  const keys = Object.keys(record).sort();
  if (keys.length !== fields.length || keys.some((key, index) => key !== fields[index])) {
    deny(reasonCode);
  }
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

function requireReasonCode(value) {
  if (!REASON_CODE.test(value ?? "")) deny("REASON_CODE_INVALID");
  return value;
}

function requirePositiveVersion(value, reasonCode) {
  if (!Number.isSafeInteger(value) || value < 1) deny(reasonCode);
  return value;
}

function requireUtcNow(clock) {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) deny("CONFIGURATION_TIME_INVALID");
  return value.toISOString();
}

function normalizeDraftRequest(value) {
  const input = requireExactFields(value, DRAFT_FIELDS, "DRAFT_REQUEST_INVALID");
  if (typeof input.maximumSourceInfluence !== "number"
    || !Number.isFinite(input.maximumSourceInfluence)
    || input.maximumSourceInfluence <= 0
    || input.maximumSourceInfluence > 1) {
    deny("CONFIGURATION_INVALID");
  }
  try {
    const model = defineTrustModelConfiguration({
      modelVersion: input.modelVersion,
      weights: input.weights,
    });
    const temporal = defineTemporalTrustConfiguration({
      initialScore: input.initialScore,
      smoothingAlpha: input.smoothingAlpha,
      staleAfterSeconds: input.staleAfterSeconds,
    });
    return deepFreeze({
      modelVersion: model.modelVersion,
      initialScore: temporal.initialScore,
      smoothingAlpha: temporal.smoothingAlpha,
      maximumSourceInfluence: input.maximumSourceInfluence,
      staleAfterSeconds: temporal.staleAfterSeconds,
      weights: model.weights,
      reasonCode: requireReasonCode(input.reasonCode),
    });
  } catch (error) {
    if (error instanceof TrustModelDefinitionError || error instanceof TrustSmoothingError) {
      deny("CONFIGURATION_INVALID");
    }
    throw error;
  }
}

function canonicalUtcOrNull(value) {
  if (value === null) return null;
  if (typeof value !== "string" || !value.endsWith("Z")) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value ? value : false;
}

function validScore(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
}

function validateConfiguration(value, expectedTenantId) {
  if (!value
    || value.tenantId !== expectedTenantId
    || !TENANT_ID.test(value.tenantId ?? "")
    || !SUBJECT_ID.test(value.createdBySubjectId ?? "")
    || !CONFIGURATION_STATES.has(value.state)
    || !Number.isSafeInteger(value.configurationVersion)
    || value.configurationVersion < 1
    || typeof value.modelVersion !== "string"
    || !validScore(value.initialScore)
    || typeof value.smoothingAlpha !== "number"
    || value.smoothingAlpha <= 0
    || value.smoothingAlpha > 1
    || typeof value.maximumSourceInfluence !== "number"
    || value.maximumSourceInfluence <= 0
    || value.maximumSourceInfluence > 1
    || !Number.isSafeInteger(value.staleAfterSeconds)
    || value.staleAfterSeconds < 1
    || !value.weights
    || canonicalUtcOrNull(value.activatedAt) === false
    || canonicalUtcOrNull(value.supersededAt) === false
    || canonicalUtcOrNull(value.createdAt) === false
    || canonicalUtcOrNull(value.updatedAt) === false) {
    deny("CONFIGURATION_RESULT_INVALID");
  }
  try {
    defineTrustModelConfiguration({ modelVersion: value.modelVersion, weights: value.weights });
  } catch (error) {
    if (error instanceof TrustModelDefinitionError) deny("CONFIGURATION_RESULT_INVALID");
    throw error;
  }
  return deepFreeze(structuredClone(value));
}

function validateDraftResult(value, context, expected) {
  const result = validateConfiguration(value, context.tenantId);
  if (result.state !== "draft"
    || result.createdBySubjectId !== context.subjectId
    || result.modelVersion !== expected.modelVersion
    || result.initialScore !== expected.initialScore
    || result.smoothingAlpha !== expected.smoothingAlpha
    || result.maximumSourceInfluence !== expected.maximumSourceInfluence
    || result.staleAfterSeconds !== expected.staleAfterSeconds
    || Object.keys(expected.weights).some((key) => result.weights[key] !== expected.weights[key])) {
    deny("CONFIGURATION_WRITE_UNCONFIRMED");
  }
  return result;
}

function validateLifecycleResult(value, context, expectedVersion) {
  const result = validateConfiguration(value, context.tenantId);
  if (result.state !== "active"
    || result.configurationVersion !== expectedVersion
    || result.activatedAt === null
    || result.supersededAt !== null) {
    deny("CONFIGURATION_WRITE_UNCONFIRMED");
  }
  return result;
}

export function createTrustConfigurationManagementService({
  repository,
  clock = () => new Date(),
} = {}) {
  if (!repository
    || typeof repository.createDraft !== "function"
    || typeof repository.activate !== "function"
    || typeof repository.rollback !== "function"
    || typeof repository.listHistory !== "function"
    || typeof clock !== "function") {
    throw new TypeError("A complete trust configuration repository and clock are required.");
  }

  return Object.freeze({
    async createDraft({ context: contextValue, request, signal } = {}) {
      const context = requireAdminContext(contextValue);
      const normalized = normalizeDraftRequest(request);
      const result = await repository.createDraft({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
        ...normalized,
        occurredAt: requireUtcNow(clock),
      }, { signal });
      return validateDraftResult(result, context, normalized);
    },

    async activate({ context: contextValue, request, signal } = {}) {
      const context = requireAdminContext(contextValue);
      const input = requireExactFields(request, ACTIVATE_FIELDS, "ACTIVATION_REQUEST_INVALID");
      const configurationVersion = requirePositiveVersion(
        input.configurationVersion,
        "CONFIGURATION_VERSION_INVALID",
      );
      const result = await repository.activate({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
        configurationVersion,
        reasonCode: requireReasonCode(input.reasonCode),
        occurredAt: requireUtcNow(clock),
      }, { signal });
      return validateLifecycleResult(result, context, configurationVersion);
    },

    async rollback({ context: contextValue, request, signal } = {}) {
      const context = requireAdminContext(contextValue);
      const input = requireExactFields(request, ROLLBACK_FIELDS, "ROLLBACK_REQUEST_INVALID");
      const targetConfigurationVersion = requirePositiveVersion(
        input.targetConfigurationVersion,
        "ROLLBACK_TARGET_INVALID",
      );
      const result = await repository.rollback({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
        targetConfigurationVersion,
        reasonCode: requireReasonCode(input.reasonCode),
        occurredAt: requireUtcNow(clock),
      }, { signal });
      const restored = validateConfiguration(result, context.tenantId);
      if (restored.state !== "active"
        || restored.configurationVersion <= targetConfigurationVersion
        || restored.createdBySubjectId !== context.subjectId
        || restored.activatedAt === null
        || restored.supersededAt !== null) {
        deny("CONFIGURATION_WRITE_UNCONFIRMED");
      }
      return restored;
    },

    async history({ context: contextValue, signal } = {}) {
      const context = requireAdminContext(contextValue);
      const rows = await repository.listHistory({
        tenantId: context.tenantId,
        actorSubjectId: context.subjectId,
      }, { signal });
      if (!Array.isArray(rows) || rows.length === 0) deny("CONFIGURATION_HISTORY_INVALID");
      const versions = new Set();
      const history = rows.map((row) => {
        const configuration = validateConfiguration(row, context.tenantId);
        if (versions.has(configuration.configurationVersion)
          || (configuration.latestEventType !== null
            && !EVENT_TYPES.has(configuration.latestEventType))) {
          deny("CONFIGURATION_HISTORY_INVALID");
        }
        versions.add(configuration.configurationVersion);
        return configuration;
      });
      if (history.some((row, index) => index > 0
        && row.configurationVersion >= history[index - 1].configurationVersion)) {
        deny("CONFIGURATION_HISTORY_INVALID");
      }
      return deepFreeze(history);
    },
  });
}

function canonicalTimestamp(value) {
  if (value === null || value === undefined) return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) deny("CONFIGURATION_RESULT_INVALID");
  return parsed.toISOString();
}

function mapConfiguration(row) {
  if (!row) deny("CONFIGURATION_RESULT_INVALID");
  return {
    tenantId: row.tenant_id,
    configurationVersion: Number(row.configuration_version),
    modelVersion: row.model_version,
    state: row.state,
    initialScore: Number(row.initial_score),
    smoothingAlpha: Number(row.smoothing_alpha),
    maximumSourceInfluence: Number(row.maximum_source_influence),
    staleAfterSeconds: Number(row.stale_after_seconds),
    weights: {
      identity: Number(row.identity_weight),
      device: Number(row.device_weight),
      behaviour: Number(row.behaviour_weight),
      certificate: Number(row.certificate_weight),
      compliance: Number(row.compliance_weight),
    },
    createdBySubjectId: row.created_by_subject_id,
    activatedAt: canonicalTimestamp(row.activated_at),
    supersededAt: canonicalTimestamp(row.superseded_at),
    createdAt: canonicalTimestamp(row.created_at),
    updatedAt: canonicalTimestamp(row.updated_at),
    latestEventType: row.latest_event_type ?? null,
    latestReasonCode: row.latest_reason_code ?? null,
    latestActorSubjectId: row.latest_actor_subject_id ?? null,
    previousActiveConfigurationVersion: row.previous_active_configuration_version == null
      ? null : Number(row.previous_active_configuration_version),
    rollbackTargetConfigurationVersion: row.rollback_target_configuration_version == null
      ? null : Number(row.rollback_target_configuration_version),
    latestEventAt: canonicalTimestamp(row.latest_event_at),
  };
}

function requireSingleRow(result) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
    deny("CONFIGURATION_WRITE_UNCONFIRMED");
  }
  return result.rows[0];
}

export function createPostgresTrustConfigurationRepository({ query } = {}) {
  if (typeof query !== "function") {
    throw new TypeError("A transaction-bound PostgreSQL query function is required.");
  }
  return Object.freeze({
    async createDraft(record, { signal } = {}) {
      const result = await query(CREATE_DRAFT_SQL, [
        record.modelVersion,
        record.initialScore,
        record.smoothingAlpha,
        record.maximumSourceInfluence,
        record.staleAfterSeconds,
        record.weights.identity,
        record.weights.device,
        record.weights.behaviour,
        record.weights.certificate,
        record.weights.compliance,
        record.reasonCode,
        record.occurredAt,
      ], { signal });
      return mapConfiguration(requireSingleRow(result));
    },
    async activate(record, { signal } = {}) {
      const result = await query(ACTIVATE_SQL, [
        record.configurationVersion,
        record.reasonCode,
        record.occurredAt,
      ], { signal });
      return mapConfiguration(requireSingleRow(result));
    },
    async rollback(record, { signal } = {}) {
      const result = await query(ROLLBACK_SQL, [
        record.targetConfigurationVersion,
        record.reasonCode,
        record.occurredAt,
      ], { signal });
      return mapConfiguration(requireSingleRow(result));
    },
    async listHistory(_record, { signal } = {}) {
      const result = await query(HISTORY_SQL, [], { signal });
      if (!result || !Array.isArray(result.rows)) deny("CONFIGURATION_HISTORY_INVALID");
      return result.rows.map(mapConfiguration);
    },
  });
}

export function trustConfigurationManagementSafeDenial(error) {
  if (!(error instanceof TrustConfigurationManagementError)) throw error;
  return TRUST_CONFIGURATION_MANAGEMENT_DENIAL;
}
