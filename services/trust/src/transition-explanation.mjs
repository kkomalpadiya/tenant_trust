import { createHash, randomUUID } from "node:crypto";
import {
  TRUST_COMPONENT_IDS,
  defineTrustModelConfiguration,
} from "@tenant-trust/trust-model";
import { calculateWeightedTrustScore } from "./weighted-score.mjs";
import {
  advanceSmoothedTrustScore,
  defineTemporalTrustConfiguration,
} from "./temporal-smoothing.mjs";
import {
  applyTrustTransitionControls,
  initializeTrustControlState,
} from "./trust-transition-controls.mjs";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRANSITION_ID = /^trn_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MODEL_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const PRODUCER_SERVICE = /^[a-z][a-z0-9-]{1,62}$/u;
const INTERNAL_BANDS = new Set(["low", "medium", "high"]);
const TRANSITION_KINDS = new Set(["held", "deteriorated", "recovered", "critical-override"]);
const INPUT_KEYS = new Set([
  "tenantId", "subjectId", "updateVersion", "correlationId", "causationId",
  "components", "evidenceReferences", "configuration", "observedAt", "source",
  "criticalEvidence",
]);
const CONFIGURATION_KEYS = new Set([
  "modelVersion", "configurationVersion", "initialScore", "smoothingAlpha",
  "staleAfterSeconds", "weights",
]);
const REFERENCE_KEYS = new Set(["evidenceId", "sourceEventId", "evidenceType"]);
const PREVIOUS_KEYS = new Set([
  "transitionId", "updateVersion", "score", "band", "recoveryStreak", "temporalState",
]);

const RECORD_SQL = `
  SELECT * FROM trust.record_subject_trust_transition(
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21,
    $22::jsonb, $23, $24, $25, $26
  )
`;

export const TRUST_EXPLANATION_POLICY = deepFreeze({
  canonicalization: "tenant-trust-json-v1",
  digest: "sha256",
  componentOrder: [...TRUST_COMPONENT_IDS],
  eventType: "trust.updated.v1",
  eventBandMapping: {
    low: "restricted",
    medium: "conditional",
    high: "trusted",
  },
});

export class TrustTransitionExplanationError extends Error {
  constructor(reasonCode) {
    super("Trust transition explanation is invalid.");
    this.name = "TrustTransitionExplanationError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new TrustTransitionExplanationError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`,
    ).join(",")}}`;
  }
  fail("CANONICAL_CONTENT_INVALID");
}

export function canonicalizeTrustExplanation(value) {
  return canonicalValue(value);
}

function requireCanonicalUtc(value, reasonCode) {
  if (typeof value !== "string" || !value.endsWith("Z")) fail(reasonCode);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) fail(reasonCode);
  return value;
}

function normalizeProducer(value) {
  if (!isPlainObject(value)
    || Object.keys(value).length !== 2
    || !PRODUCER_SERVICE.test(value.service ?? "")
    || typeof value.instanceId !== "string"
    || value.instanceId.length < 1
    || value.instanceId.length > 128) {
    fail("TRUST_EVENT_PRODUCER_INVALID");
  }
  return Object.freeze({ service: value.service, instanceId: value.instanceId });
}

function normalizeConfiguration(value) {
  if (!hasExactKeys(value, CONFIGURATION_KEYS)
    || !MODEL_VERSION.test(value.modelVersion ?? "")
    || !Number.isSafeInteger(value.configurationVersion)
    || value.configurationVersion < 1) {
    fail("TRUST_CONFIGURATION_INVALID");
  }
  let model;
  let temporal;
  try {
    model = defineTrustModelConfiguration({
      modelVersion: value.modelVersion,
      weights: value.weights,
    });
    temporal = defineTemporalTrustConfiguration({
      initialScore: value.initialScore,
      smoothingAlpha: value.smoothingAlpha,
      staleAfterSeconds: value.staleAfterSeconds,
    });
  } catch {
    fail("TRUST_CONFIGURATION_INVALID");
  }
  return deepFreeze({
    modelVersion: model.modelVersion,
    configurationVersion: value.configurationVersion,
    initialScore: temporal.initialScore,
    smoothingAlpha: temporal.smoothingAlpha,
    staleAfterSeconds: temporal.staleAfterSeconds,
    weights: model.weights,
  });
}

function normalizeReferences(value) {
  if (!Array.isArray(value) || value.length !== TRUST_COMPONENT_IDS.length) {
    fail("EVIDENCE_REFERENCE_SET_INVALID");
  }
  const references = value.map((reference) => {
    if (!hasExactKeys(reference, REFERENCE_KEYS)
      || !EVIDENCE_ID.test(reference.evidenceId ?? "")
      || !EVENT_ID.test(reference.sourceEventId ?? "")
      || !TRUST_COMPONENT_IDS.includes(reference.evidenceType)) {
      fail("EVIDENCE_REFERENCE_SET_INVALID");
    }
    return { ...reference };
  });
  if (new Set(references.map(({ evidenceType }) => evidenceType)).size !== references.length
    || new Set(references.map(({ evidenceId }) => evidenceId)).size !== references.length
    || new Set(references.map(({ sourceEventId }) => sourceEventId)).size !== references.length) {
    fail("EVIDENCE_REFERENCE_SET_INVALID");
  }
  const byType = new Map(references.map((reference) => [reference.evidenceType, reference]));
  return deepFreeze(TRUST_COMPONENT_IDS.map((componentId) => byType.get(componentId)));
}

function normalizePrevious(value, configuration, updateVersion, evaluatedAt) {
  if (value === null || value === undefined) return null;
  if (!hasExactKeys(value, PREVIOUS_KEYS)
    || !TRANSITION_ID.test(value.transitionId ?? "")
    || !Number.isSafeInteger(value.updateVersion)
    || value.updateVersion < 1
    || value.updateVersion >= updateVersion
    || typeof value.score !== "number"
    || !Number.isFinite(value.score)
    || value.score < 0
    || value.score > 100
    || !INTERNAL_BANDS.has(value.band)
    || !Number.isSafeInteger(value.recoveryStreak)
    || value.recoveryStreak < 0
    || !isPlainObject(value.temporalState)
    || value.temporalState.score !== value.score) {
    fail("PREVIOUS_TRANSITION_INVALID");
  }
  try {
    advanceSmoothedTrustScore({
      configuration: {
        initialScore: configuration.initialScore,
        smoothingAlpha: configuration.smoothingAlpha,
        staleAfterSeconds: configuration.staleAfterSeconds,
      },
      previousState: value.temporalState,
      observation: null,
      evaluatedAt,
    });
    applyTrustTransitionControls({
      previousState: {
        score: value.score,
        band: value.band,
        recoveryStreak: value.recoveryStreak,
      },
      candidateScore: value.score,
      source: {
        sourceId: "src_00000000-0000-4000-8000-000000000000",
        maximumInfluence: 1,
        corroboratingSourceIds: [],
      },
    });
  } catch {
    fail("PREVIOUS_TRANSITION_INVALID");
  }
  return deepFreeze(structuredClone(value));
}

function externalBand(internalBand) {
  return TRUST_EXPLANATION_POLICY.eventBandMapping[internalBand];
}

function contributionRecords(weighted, references) {
  const referenceByType = new Map(references.map((item) => [item.evidenceType, item]));
  return deepFreeze(TRUST_COMPONENT_IDS.map((componentId) => ({
    componentId,
    normalizedValue: weighted.contributions[componentId].normalizedValue,
    weight: weighted.contributions[componentId].weight,
    weightedContribution: weighted.contributions[componentId].weightedContribution,
    evidenceId: referenceByType.get(componentId).evidenceId,
    sourceEventId: referenceByType.get(componentId).sourceEventId,
  })));
}

export function buildTrustTransitionExplanation({
  transitionId,
  eventId,
  producer: producerValue,
  evaluatedAt,
  input: inputValue,
  previousTransition: previousValue = null,
} = {}) {
  if (!TRANSITION_ID.test(transitionId ?? "") || !EVENT_ID.test(eventId ?? "")) {
    fail("TRUST_TRANSITION_IDENTITY_INVALID");
  }
  if (!hasExactKeys(inputValue, INPUT_KEYS)
    || !TENANT_ID.test(inputValue.tenantId ?? "")
    || !SUBJECT_ID.test(inputValue.subjectId ?? "")
    || !Number.isSafeInteger(inputValue.updateVersion)
    || inputValue.updateVersion < 1
    || !CORRELATION_ID.test(inputValue.correlationId ?? "")
    || !EVENT_ID.test(inputValue.causationId ?? "")) {
    fail("TRUST_TRANSITION_INPUT_INVALID");
  }
  requireCanonicalUtc(evaluatedAt, "TRUST_EVALUATION_TIME_INVALID");
  requireCanonicalUtc(inputValue.observedAt, "TRUST_OBSERVATION_TIME_INVALID");
  if (Date.parse(inputValue.observedAt) > Date.parse(evaluatedAt)) {
    fail("TRUST_OBSERVATION_TIME_INVALID");
  }
  const producer = normalizeProducer(producerValue);
  const configuration = normalizeConfiguration(inputValue.configuration);
  const evidenceReferences = normalizeReferences(inputValue.evidenceReferences);
  if (!evidenceReferences.some(({ sourceEventId }) => sourceEventId === inputValue.causationId)) {
    fail("TRUST_CAUSATION_INVALID");
  }
  const previousTransition = normalizePrevious(
    previousValue,
    configuration,
    inputValue.updateVersion,
    evaluatedAt,
  );

  let weighted;
  let temporal;
  let controlled;
  try {
    weighted = calculateWeightedTrustScore(inputValue.components, {
      modelVersion: configuration.modelVersion,
      weights: configuration.weights,
    });
    temporal = advanceSmoothedTrustScore({
      configuration: {
        initialScore: configuration.initialScore,
        smoothingAlpha: configuration.smoothingAlpha,
        staleAfterSeconds: configuration.staleAfterSeconds,
      },
      previousState: previousTransition?.temporalState ?? null,
      observation: { score: weighted.score, observedAt: inputValue.observedAt },
      evaluatedAt,
    });
    controlled = applyTrustTransitionControls({
      previousState: previousTransition
        ? {
            score: previousTransition.score,
            band: previousTransition.band,
            recoveryStreak: previousTransition.recoveryStreak,
          }
        : initializeTrustControlState(configuration.initialScore),
      candidateScore: temporal.score,
      source: inputValue.source,
      criticalEvidence: inputValue.criticalEvidence,
    });
  } catch {
    fail("TRUST_CALCULATION_INVALID");
  }

  const contributions = contributionRecords(weighted, evidenceReferences);
  const previousState = previousTransition
    ? {
        transitionId: previousTransition.transitionId,
        updateVersion: previousTransition.updateVersion,
        score: previousTransition.score,
        band: previousTransition.band,
        recoveryStreak: previousTransition.recoveryStreak,
        temporalState: previousTransition.temporalState,
      }
    : {
        transitionId: null,
        updateVersion: null,
        score: configuration.initialScore,
        band: "uninitialized",
        recoveryStreak: 0,
        temporalState: null,
      };
  const newState = {
    score: controlled.score,
    band: controlled.band,
    recoveryStreak: controlled.recoveryStreak,
    temporalState: temporal.temporalState,
  };
  const explanation = deepFreeze({
    schemaVersion: "1.0.0",
    transitionId,
    tenantId: inputValue.tenantId,
    subjectId: inputValue.subjectId,
    updateVersion: inputValue.updateVersion,
    modelVersion: configuration.modelVersion,
    configurationVersion: configuration.configurationVersion,
    observedAt: inputValue.observedAt,
    evaluatedAt,
    previousState,
    newState,
    evidenceReferences,
    weightedCalculation: {
      method: weighted.method,
      score: weighted.score,
      normalization: weighted.normalization,
      rounding: weighted.rounding,
      contributions,
    },
    temporalCalculation: {
      phase: temporal.phase,
      observationStatus: temporal.observationStatus,
      score: temporal.score,
      calculation: temporal.calculation,
      policy: temporal.policy,
    },
    transitionControl: {
      transition: controlled.transition,
      sourceInfluence: controlled.sourceInfluence,
      recovery: controlled.recovery,
      criticalOverride: controlled.criticalOverride,
      policy: controlled.policy,
      configuration: controlled.configuration,
    },
    policy: TRUST_EXPLANATION_POLICY,
  });
  const explanationJson = canonicalizeTrustExplanation(explanation);
  const explanationHashSha256 = createHash("sha256").update(explanationJson, "utf8").digest("hex");
  const event = deepFreeze({
    schemaVersion: "1.0.0",
    eventId,
    eventType: "trust.updated.v1",
    tenantId: inputValue.tenantId,
    subjectId: inputValue.subjectId,
    aggregateId: transitionId,
    correlationId: inputValue.correlationId,
    causationId: inputValue.causationId,
    idempotencyKey: `trust-transition:${transitionId}`,
    occurredAt: evaluatedAt,
    recordedAt: evaluatedAt,
    producer,
    payload: {
      transitionId,
      previousScore: previousState.score,
      newScore: newState.score,
      previousBand: previousState.band === "uninitialized"
        ? "uninitialized"
        : externalBand(previousState.band),
      newBand: externalBand(newState.band),
      modelVersion: configuration.modelVersion,
      configurationVersion: configuration.configurationVersion,
      evidenceIds: evidenceReferences.map(({ evidenceId }) => evidenceId),
      explanationHashSha256,
    },
  });
  const eventJson = canonicalizeTrustExplanation(event);
  const eventSha256 = createHash("sha256").update(eventJson, "utf8").digest("hex");

  return deepFreeze({
    transitionId,
    eventId,
    tenantId: inputValue.tenantId,
    subjectId: inputValue.subjectId,
    updateVersion: inputValue.updateVersion,
    previousTransitionId: previousState.transitionId,
    previousState,
    newState,
    weightedScore: weighted.score,
    smoothedScore: temporal.score,
    transition: controlled.transition,
    observedAt: inputValue.observedAt,
    evaluatedAt,
    modelVersion: configuration.modelVersion,
    configurationVersion: configuration.configurationVersion,
    contributions,
    explanation,
    explanationJson,
    explanationHashSha256,
    event,
    eventJson,
    eventSha256,
  });
}

function mapConfirmation(row, expected) {
  const confirmation = {
    tenantId: row?.tenant_id,
    subjectId: row?.subject_id,
    transitionId: row?.transition_id,
    eventId: row?.event_id,
    updateVersion: Number(row?.update_version),
    explanationHashSha256: row?.explanation_hash_sha256,
    eventSha256: row?.event_sha256,
    recordedAt: new Date(row?.recorded_at).toISOString(),
  };
  if (confirmation.tenantId !== expected.tenantId
    || confirmation.subjectId !== expected.subjectId
    || confirmation.transitionId !== expected.transitionId
    || confirmation.eventId !== expected.eventId
    || confirmation.updateVersion !== expected.updateVersion
    || confirmation.explanationHashSha256 !== expected.explanationHashSha256
    || confirmation.eventSha256 !== expected.eventSha256
    || !Number.isFinite(Date.parse(confirmation.recordedAt))) {
    fail("TRUST_TRANSITION_CONFIRMATION_INVALID");
  }
  return Object.freeze(confirmation);
}

async function inTransaction(pool, operation, signal) {
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

export function createPostgresTrustTransitionRepository({ pool } = {}) {
  if (!pool || typeof pool.connect !== "function") {
    throw new TypeError("A PostgreSQL pool is required.");
  }
  return Object.freeze({
    async record(record, { signal } = {}) {
      return inTransaction(pool, async (query) => {
        const result = await query(RECORD_SQL, [
          record.tenantId,
          record.subjectId,
          record.transitionId,
          record.eventId,
          record.event.correlationId,
          record.event.causationId,
          record.updateVersion,
          record.previousTransitionId,
          record.previousState.score,
          record.previousState.band,
          record.previousState.recoveryStreak,
          record.newState.score,
          record.newState.band,
          record.newState.recoveryStreak,
          record.weightedScore,
          record.smoothedScore,
          record.transition,
          record.observedAt,
          record.evaluatedAt,
          record.modelVersion,
          record.configurationVersion,
          JSON.stringify(record.contributions),
          record.explanationJson,
          record.explanationHashSha256,
          record.eventJson,
          record.eventSha256,
        ]);
        if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
          fail("TRUST_TRANSITION_CONFIRMATION_INVALID");
        }
        return mapConfirmation(result.rows[0], record);
      }, signal);
    },
  });
}

export function createTrustTransitionExplanationService({
  repository,
  producer,
  clock = () => new Date(),
  idFactory = randomUUID,
} = {}) {
  const trustedProducer = normalizeProducer(producer);
  if (!repository || typeof repository.record !== "function"
    || typeof clock !== "function" || typeof idFactory !== "function") {
    throw new TypeError("A transition repository, producer, clock and ID factory are required.");
  }
  return Object.freeze({
    async record(input, { previousTransition = null, signal } = {}) {
      const now = clock();
      if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
        fail("TRUST_EVALUATION_TIME_INVALID");
      }
      const transitionId = `trn_${idFactory()}`;
      const eventId = `evt_${idFactory()}`;
      const record = buildTrustTransitionExplanation({
        transitionId,
        eventId,
        producer: trustedProducer,
        evaluatedAt: now.toISOString(),
        input,
        previousTransition,
      });
      const persisted = await repository.record(record, { signal });
      return deepFreeze({ ...record, persistence: persisted });
    },
  });
}
