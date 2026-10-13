import { assertNoTenantSwitch, TenantContextError } from "@tenant-trust/tenant-context";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRANSITION_ID = /^trn_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MODEL_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const STATES = new Set(["fresh", "stale", "missing"]);
const BANDS = new Set(["low", "medium", "high"]);

const LOOKUP_SQL = "SELECT * FROM trust.get_current_actor_trust_score()";

export const TRUST_SCORE_LOOKUP_POLICY = deepFreeze({
  id: "current-actor-trust-score-v1",
  freshnessBoundary: "ageSeconds <= staleAfterSeconds",
  stateAuthority: "durable-current-transition",
  staleScoreExposure: "last-known-only",
  conservativeOutcome: "DENY",
  states: ["fresh", "stale", "missing"],
});

export class TrustScoreLookupError extends Error {
  constructor(reasonCode) {
    super("Current trust score is unavailable.");
    this.name = "TrustScoreLookupError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new TrustScoreLookupError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function requireContext(value) {
  try {
    return assertNoTenantSwitch(value, []);
  } catch (error) {
    if (error instanceof TenantContextError) fail("TRUST_CONTEXT_INVALID");
    throw error;
  }
}

function finiteNumber(value) {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) ? number : null;
}

function positiveInteger(value) {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function canonicalTime(value) {
  if (typeof value !== "string" || !value.endsWith("Z")) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value ? value : null;
}

function normalizeDatabaseRow(row) {
  if (!row || typeof row !== "object" || Array.isArray(row)) {
    fail("TRUST_LOOKUP_RESULT_INVALID");
  }
  const time = (value) => {
    if (value === null || value === undefined) return null;
    const parsed = value instanceof Date ? value : new Date(value);
    return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : value;
  };
  return {
    tenantId: row.tenant_id,
    subjectId: row.subject_id,
    state: row.freshness_state,
    usableForPolicy: row.usable_for_policy,
    requiredOutcome: row.required_outcome,
    reasonCode: row.reason_code,
    policyScore: row.policy_score === null ? null : finiteNumber(row.policy_score),
    policyBand: row.policy_band,
    lastKnownScore: row.last_known_score === null ? null : finiteNumber(row.last_known_score),
    lastKnownBand: row.last_known_band,
    ageSeconds: row.age_seconds === null ? null : finiteNumber(row.age_seconds),
    staleAfterSeconds: row.stale_after_seconds === null
      ? null
      : positiveInteger(row.stale_after_seconds),
    transitionId: row.transition_id,
    updateVersion: row.update_version === null ? null : positiveInteger(row.update_version),
    modelVersion: row.model_version,
    configurationVersion: row.configuration_version === null
      ? null
      : positiveInteger(row.configuration_version),
    observedAt: time(row.observed_at),
    evaluatedAt: time(row.evaluated_at),
    recordedAt: time(row.recorded_at),
    explanationHashSha256: row.explanation_hash_sha256,
  };
}

function validateLookupResult(value, context) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.tenantId !== context.tenantId
    || value.subjectId !== context.subjectId
    || !TENANT_ID.test(value.tenantId ?? "")
    || !SUBJECT_ID.test(value.subjectId ?? "")
    || !STATES.has(value.state)
    || typeof value.usableForPolicy !== "boolean") {
    fail("TRUST_LOOKUP_RESULT_INVALID");
  }

  const commonNulls = [
    value.policyScore, value.policyBand, value.lastKnownScore, value.lastKnownBand,
    value.ageSeconds, value.staleAfterSeconds, value.transitionId, value.updateVersion,
    value.modelVersion, value.configurationVersion, value.observedAt, value.evaluatedAt,
    value.recordedAt, value.explanationHashSha256,
  ];
  if (value.state === "missing") {
    if (value.usableForPolicy
      || value.requiredOutcome !== "DENY"
      || value.reasonCode !== "TRUST_STATE_MISSING"
      || commonNulls.some((item) => item !== null)) {
      fail("TRUST_LOOKUP_RESULT_INVALID");
    }
    return deepFreeze(structuredClone(value));
  }

  const lastKnownScore = finiteNumber(value.lastKnownScore);
  const ageSeconds = finiteNumber(value.ageSeconds);
  if (lastKnownScore === null || lastKnownScore < 0 || lastKnownScore > 100
    || !BANDS.has(value.lastKnownBand)
    || ageSeconds === null || ageSeconds < 0
    || positiveInteger(value.staleAfterSeconds) === null
    || !TRANSITION_ID.test(value.transitionId ?? "")
    || positiveInteger(value.updateVersion) === null
    || !MODEL_VERSION.test(value.modelVersion ?? "")
    || positiveInteger(value.configurationVersion) === null
    || canonicalTime(value.observedAt) === null
    || canonicalTime(value.evaluatedAt) === null
    || canonicalTime(value.recordedAt) === null
    || !SHA256.test(value.explanationHashSha256 ?? "")
    || Date.parse(value.observedAt) > Date.parse(value.evaluatedAt)
    || Date.parse(value.evaluatedAt) > Date.parse(value.recordedAt) + 2000) {
    fail("TRUST_LOOKUP_RESULT_INVALID");
  }

  if (value.state === "fresh") {
    if (!value.usableForPolicy
      || value.requiredOutcome !== null
      || value.reasonCode !== null
      || finiteNumber(value.policyScore) !== lastKnownScore
      || value.policyBand !== value.lastKnownBand
      || ageSeconds > value.staleAfterSeconds) {
      fail("TRUST_LOOKUP_RESULT_INVALID");
    }
  } else if (value.usableForPolicy
    || value.requiredOutcome !== "DENY"
    || value.reasonCode !== "TRUST_STATE_STALE"
    || value.policyScore !== null
    || value.policyBand !== null
    || ageSeconds <= value.staleAfterSeconds) {
    fail("TRUST_LOOKUP_RESULT_INVALID");
  }
  return deepFreeze(structuredClone(value));
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original failure.
  }
}

export function createPostgresTrustScoreLookupRepository({ pool } = {}) {
  if (!pool || typeof pool.connect !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }
  return Object.freeze({
    async lookup(contextValue, { signal } = {}) {
      const context = requireContext(contextValue);
      const client = await pool.connect();
      const query = (text, values = []) => client.query({ text, values, signal });
      try {
        await query("BEGIN");
        await query("SET LOCAL ROLE tenant_trust_app");
        await query(
          "SELECT identity.set_tenant_actor_context($1::identity.tenant_id, $2::identity.subject_id)",
          [context.tenantId, context.subjectId],
        );
        const result = await query(LOOKUP_SQL);
        if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
          fail("TRUST_LOOKUP_RESULT_INVALID");
        }
        const mapped = normalizeDatabaseRow(result.rows[0]);
        await query("COMMIT");
        return validateLookupResult(mapped, context);
      } catch (error) {
        await rollbackQuietly(client);
        throw error;
      } finally {
        client.release();
      }
    },
  });
}

export function createTrustScoreLookupService({ repository } = {}) {
  if (!repository || typeof repository.lookup !== "function") {
    throw new TypeError("A trust-score lookup repository is required.");
  }
  return Object.freeze({
    async lookup({ context: contextValue, signal } = {}) {
      const context = requireContext(contextValue);
      const result = await repository.lookup(context, { signal });
      return validateLookupResult(result, context);
    },
  });
}
