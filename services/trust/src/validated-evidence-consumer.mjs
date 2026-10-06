import { createEvidenceAcceptedConsumer } from "@tenant-trust/evidence-events";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CONSUMER_NAME = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const EVIDENCE_TYPES = new Set(["identity", "device", "behaviour", "certificate", "compliance"]);
const OUTCOMES = new Set(["duplicate", "superseded", "staged", "state_updated"]);
const CONSUME_SQL = `
  SELECT * FROM trust.consume_validated_evidence_component(
    $1, $2, $3, $4, $5, $6, $7, $8
  )
`;

export const VALIDATED_EVIDENCE_CONSUMPTION_POLICY = Object.freeze({
  deliverySemantics: "at-least-once-delivery-exactly-once-effect",
  aggregateScope: "tenant-and-subject",
  concurrencyControl: "transaction-advisory-lock-per-tenant-subject",
  ordering: "observed-at-then-stream-sequence-then-event-id",
  incompleteEvidence: "stage-until-all-five-components-exist",
  olderEvidence: "record-effect-without-state-rollback",
});

export class ValidatedEvidenceConsumptionError extends Error {
  constructor(reasonCode) {
    super("Validated evidence trust consumption failed.");
    this.name = "ValidatedEvidenceConsumptionError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new ValidatedEvidenceConsumptionError(reasonCode);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function normalizeComponentScore(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 100) {
    fail("COMPONENT_SCORE_INVALID");
  }
  return value;
}

function normalizeConsumptionRequest({
  consumerName,
  event,
  verified,
  streamSequence,
  signedEventSha256,
  componentScore,
  processedAt,
}) {
  const evidenceType = verified?.payload?.evidenceType;
  if (!CONSUMER_NAME.test(consumerName ?? "")
    || !TENANT_ID.test(event?.tenantId ?? "")
    || !SUBJECT_ID.test(verified?.subjectId ?? "")
    || !EVENT_ID.test(event?.eventId ?? "")
    || !EVIDENCE_ID.test(event?.aggregateId ?? "")
    || event.tenantId !== verified?.tenantId
    || event.eventId !== verified?.eventId
    || event.aggregateId !== verified?.aggregateId
    || !EVIDENCE_TYPES.has(evidenceType)
    || evidenceType !== event?.payload?.evidenceType
    || !Number.isSafeInteger(streamSequence)
    || streamSequence < 1
    || !SHA256.test(signedEventSha256 ?? "")
    || typeof processedAt !== "string"
    || new Date(processedAt).toISOString() !== processedAt) {
    fail("CONSUMPTION_REQUEST_INVALID");
  }
  return Object.freeze({
    consumerName,
    tenantId: event.tenantId,
    subjectId: verified.subjectId,
    eventId: event.eventId,
    evidenceId: event.aggregateId,
    evidenceType,
    streamSequence,
    signedEventSha256,
    componentScore: normalizeComponentScore(componentScore),
    processedAt,
  });
}

function mapConsumptionResult(row, request) {
  if (!row
    || typeof row.applied !== "boolean"
    || !OUTCOMES.has(row.outcome_code)
    || row.tenant_id !== request.tenantId
    || row.subject_id !== request.subjectId
    || row.evidence_type !== request.evidenceType) {
    fail("CONSUMPTION_RESULT_INVALID");
  }
  const updateVersion = row.update_version === null || row.update_version === undefined
    ? null
    : Number(row.update_version);
  if (updateVersion !== null
    && (!Number.isSafeInteger(updateVersion) || updateVersion < 1)) {
    fail("CONSUMPTION_RESULT_INVALID");
  }
  if (row.outcome_code === "state_updated" && updateVersion === null) {
    fail("CONSUMPTION_RESULT_INVALID");
  }
  if ((row.outcome_code === "duplicate") !== !row.applied) {
    fail("CONSUMPTION_RESULT_INVALID");
  }
  return deepFreeze({
    applied: row.applied,
    outcome: row.outcome_code,
    tenantId: row.tenant_id,
    subjectId: row.subject_id,
    evidenceType: row.evidence_type,
    updateVersion,
  });
}

async function inConsumerTransaction(pool, operation, signal) {
  const client = await pool.connect();
  const query = (text, values) => client.query({ text, values, signal });
  try {
    await query("BEGIN");
    await query("SET LOCAL ROLE tenant_trust_evidence_event_consumer");
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

export function createPostgresValidatedEvidenceRepository({ pool, clock = () => new Date() } = {}) {
  if (!pool || typeof pool.connect !== "function" || typeof clock !== "function") {
    throw new TypeError("A PostgreSQL pool and clock are required.");
  }
  return Object.freeze({
    async consume(input, { signal } = {}) {
      const now = clock();
      if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
        fail("CONSUMPTION_CLOCK_INVALID");
      }
      const request = normalizeConsumptionRequest({
        ...input,
        processedAt: now.toISOString(),
      });
      return inConsumerTransaction(pool, async (query) => {
        const result = await query(CONSUME_SQL, [
          request.consumerName,
          request.tenantId,
          request.eventId,
          request.evidenceId,
          request.streamSequence,
          request.signedEventSha256,
          request.componentScore,
          request.processedAt,
        ]);
        if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
          fail("CONSUMPTION_RESULT_INVALID");
        }
        return mapConsumptionResult(result.rows[0], request);
      }, signal);
    },
  });
}

export function createValidatedEvidenceTrustConsumer({
  consumerName,
  verifyEvent,
  resolveComponentScore,
  repository,
} = {}) {
  if (!CONSUMER_NAME.test(consumerName ?? "")
    || typeof verifyEvent !== "function"
    || typeof resolveComponentScore !== "function"
    || !repository
    || typeof repository.consume !== "function") {
    throw new TypeError(
      "A consumer name, event verifier, component-score resolver and repository are required.",
    );
  }

  return Object.freeze({
    async consume({ event, streamSequence, expectedTenantId, resolvePublicKey, signal } = {}) {
      let persistenceResult;
      const delegate = createEvidenceAcceptedConsumer({
        consumerName,
        verifyEvent,
        async consumeOnce(delivery) {
          const componentScore = normalizeComponentScore(await resolveComponentScore({
            event: delivery.event,
            verified: delivery.verified,
            signal,
          }));
          persistenceResult = await repository.consume({
            ...delivery,
            componentScore,
          }, { signal });
          return persistenceResult.applied;
        },
      });

      const deliveryResult = await delegate.consume({
        event,
        streamSequence,
        expectedTenantId,
        resolvePublicKey,
        applyEffect: async () => {},
      });
      if (!persistenceResult) fail("CONSUMPTION_RESULT_INVALID");
      return deepFreeze({
        ...deliveryResult,
        outcome: persistenceResult.outcome,
        tenantId: persistenceResult.tenantId,
        subjectId: persistenceResult.subjectId,
        evidenceType: persistenceResult.evidenceType,
        updateVersion: persistenceResult.updateVersion,
      });
    },
  });
}
