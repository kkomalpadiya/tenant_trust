import {
  TRUST_COMPONENT_IDS,
  TrustModelDefinitionError,
  defineNormalizedComponents,
} from "@tenant-trust/trust-model";

export {
  WEIGHTED_SCORE_METHOD,
  WEIGHTED_SCORE_NORMALIZATION,
  WEIGHTED_SCORE_ROUNDING,
  calculateWeightedTrustScore,
} from "./weighted-score.mjs";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MODEL_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const COMPONENT_SET = new Set(TRUST_COMPONENT_IDS);
const WRITE_KEYS = new Set([
  "tenantId",
  "subjectId",
  "expectedPreviousVersion",
  "modelVersion",
  "configurationVersion",
  "components",
  "observedAt",
  "evidenceReferences",
]);
const REFERENCE_KEYS = new Set(["evidenceId", "sourceEventId", "evidenceType"]);

const STORE_SQL = `
  SELECT * FROM trust.store_subject_trust_state(
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11, $12::jsonb
  )
`;
const CURRENT_SQL = "SELECT * FROM trust.get_current_subject_trust_state($1, $2)";
const VERSION_SQL = "SELECT * FROM trust.get_subject_trust_state_version($1, $2, $3)";

export class TrustStateStorageError extends Error {
  constructor(reasonCode) {
    super("Trust-state storage request is invalid.");
    this.name = "TrustStateStorageError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new TrustStateStorageError(reasonCode);
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value, expected) {
  return isPlainObject(value)
    && Object.keys(value).length === expected.size
    && Object.keys(value).every((key) => expected.has(key));
}

function canonicalUtc(value) {
  if (typeof value !== "string" || !value.endsWith("Z")) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function normalizeReference(reference) {
  if (!hasExactKeys(reference, REFERENCE_KEYS)
    || !EVIDENCE_ID.test(reference.evidenceId ?? "")
    || !EVENT_ID.test(reference.sourceEventId ?? "")
    || !COMPONENT_SET.has(reference.evidenceType)) {
    fail("EVIDENCE_REFERENCE_INVALID");
  }
  return Object.freeze({
    evidenceId: reference.evidenceId,
    sourceEventId: reference.sourceEventId,
    evidenceType: reference.evidenceType,
  });
}

function normalizeReferenceSet(value, invalidReasonCode) {
  if (!Array.isArray(value) || value.length !== TRUST_COMPONENT_IDS.length) {
    fail(invalidReasonCode);
  }
  const references = value.map(normalizeReference);
  if (new Set(references.map(({ evidenceType }) => evidenceType)).size !== TRUST_COMPONENT_IDS.length
    || new Set(references.map(({ evidenceId }) => evidenceId)).size !== references.length
    || new Set(references.map(({ sourceEventId }) => sourceEventId)).size !== references.length) {
    fail(invalidReasonCode);
  }
  const byType = new Map(references.map((reference) => [reference.evidenceType, reference]));
  return Object.freeze(TRUST_COMPONENT_IDS.map((componentId) => byType.get(componentId)));
}

export function normalizeTrustStateWrite(value) {
  if (!hasExactKeys(value, WRITE_KEYS)
    || !TENANT_ID.test(value.tenantId ?? "")
    || !SUBJECT_ID.test(value.subjectId ?? "")
    || !Number.isSafeInteger(value.expectedPreviousVersion)
    || value.expectedPreviousVersion < 0
    || !MODEL_VERSION.test(value.modelVersion ?? "")
    || !Number.isSafeInteger(value.configurationVersion)
    || value.configurationVersion < 1
    || !canonicalUtc(value.observedAt)
    || !Array.isArray(value.evidenceReferences)
    || value.evidenceReferences.length !== TRUST_COMPONENT_IDS.length) {
    fail("TRUST_STATE_WRITE_INVALID");
  }

  let components;
  try {
    components = defineNormalizedComponents(value.components);
  } catch (error) {
    if (error instanceof TrustModelDefinitionError) fail("TRUST_COMPONENTS_INVALID");
    throw error;
  }

  const evidenceReferences = normalizeReferenceSet(
    value.evidenceReferences,
    "EVIDENCE_REFERENCE_SET_INVALID",
  );
  return Object.freeze({
    tenantId: value.tenantId,
    subjectId: value.subjectId,
    expectedPreviousVersion: value.expectedPreviousVersion,
    modelVersion: value.modelVersion,
    configurationVersion: value.configurationVersion,
    components,
    observedAt: value.observedAt,
    evidenceReferences,
  });
}

function normalizeReadIdentity({ tenantId, subjectId, updateVersion } = {}) {
  if (!TENANT_ID.test(tenantId ?? "") || !SUBJECT_ID.test(subjectId ?? "")) {
    fail("TRUST_STATE_READ_INVALID");
  }
  if (updateVersion !== undefined
    && (!Number.isSafeInteger(updateVersion) || updateVersion < 1)) {
    fail("TRUST_STATE_READ_INVALID");
  }
  return { tenantId, subjectId, updateVersion };
}

function normalizeEvidenceReferences(value) {
  let parsed;
  try {
    parsed = typeof value === "string" ? JSON.parse(value) : value;
    return normalizeReferenceSet(parsed, "TRUST_STATE_RESULT_INVALID");
  } catch (error) {
    if (error instanceof TrustStateStorageError || error instanceof SyntaxError) {
      fail("TRUST_STATE_RESULT_INVALID");
    }
    throw error;
  }
}

function mapState(row) {
  if (!row) return null;
  const result = {
    tenantId: row.tenant_id,
    subjectId: row.subject_id,
    updateVersion: Number(row.update_version),
    modelVersion: row.model_version,
    configurationVersion: Number(row.configuration_version),
    components: defineNormalizedComponents({
      identity: Number(row.identity_component),
      device: Number(row.device_component),
      behaviour: Number(row.behaviour_component),
      certificate: Number(row.certificate_component),
      compliance: Number(row.compliance_component),
    }),
    observedAt: new Date(row.observed_at).toISOString(),
    recordedAt: new Date(row.recorded_at).toISOString(),
    evidenceReferences: normalizeEvidenceReferences(row.evidence_references),
  };
  if (!TENANT_ID.test(result.tenantId ?? "")
    || !SUBJECT_ID.test(result.subjectId ?? "")
    || !Number.isSafeInteger(result.updateVersion)
    || result.updateVersion < 1
    || !MODEL_VERSION.test(result.modelVersion ?? "")
    || !Number.isSafeInteger(result.configurationVersion)
    || result.configurationVersion < 1
    || result.evidenceReferences.length !== TRUST_COMPONENT_IDS.length) {
    fail("TRUST_STATE_RESULT_INVALID");
  }
  return Object.freeze(result);
}

function mapWriteConfirmation(row, write) {
  if (!row) fail("TRUST_STATE_WRITE_UNCONFIRMED");
  const result = {
    tenantId: row.tenant_id,
    subjectId: row.subject_id,
    updateVersion: Number(row.update_version),
    modelVersion: row.model_version,
    configurationVersion: Number(row.configuration_version),
    observedAt: new Date(row.observed_at).toISOString(),
    recordedAt: new Date(row.recorded_at).toISOString(),
  };
  if (result.tenantId !== write.tenantId
    || result.subjectId !== write.subjectId
    || result.updateVersion !== write.expectedPreviousVersion + 1
    || result.modelVersion !== write.modelVersion
    || result.configurationVersion !== write.configurationVersion
    || result.observedAt !== write.observedAt) {
    fail("TRUST_STATE_WRITE_UNCONFIRMED");
  }
  return Object.freeze(result);
}

async function inTrustEngineTransaction(pool, operation, signal) {
  const client = await pool.connect();
  const query = (text, values) => client.query({ text, values, signal });
  try {
    await query("BEGIN");
    await query("SET LOCAL ROLE tenant_trust_trust_engine");
    const result = await operation(query);
    await query("COMMIT");
    return result;
  } catch (error) {
    try {
      await query("ROLLBACK");
    } catch {
      // Preserve the original failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

export function createPostgresTrustStateRepository({ pool } = {}) {
  if (!pool || typeof pool.connect !== "function") {
    throw new TypeError("A PostgreSQL connection pool is required.");
  }

  return Object.freeze({
    async store(value, { signal } = {}) {
      const write = normalizeTrustStateWrite(value);
      return inTrustEngineTransaction(pool, async (query) => {
        const result = await query(STORE_SQL, [
          write.tenantId,
          write.subjectId,
          write.expectedPreviousVersion,
          write.modelVersion,
          write.configurationVersion,
          write.components.identity,
          write.components.device,
          write.components.behaviour,
          write.components.certificate,
          write.components.compliance,
          write.observedAt,
          JSON.stringify(write.evidenceReferences),
        ]);
        return mapWriteConfirmation(result.rows[0], write);
      }, signal);
    },

    async getCurrent(identity, { signal } = {}) {
      const target = normalizeReadIdentity(identity);
      return inTrustEngineTransaction(pool, async (query) => {
        const result = await query(CURRENT_SQL, [target.tenantId, target.subjectId]);
        return mapState(result.rows[0]);
      }, signal);
    },

    async getVersion(identity, { signal } = {}) {
      const target = normalizeReadIdentity(identity);
      if (target.updateVersion === undefined) fail("TRUST_STATE_READ_INVALID");
      return inTrustEngineTransaction(pool, async (query) => {
        const result = await query(VERSION_SQL, [
          target.tenantId,
          target.subjectId,
          target.updateVersion,
        ]);
        return mapState(result.rows[0]);
      }, signal);
    },
  });
}
