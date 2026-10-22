import { createHash } from "node:crypto";
import { canonicalizeJson } from "@tenant-trust/certificate-events";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^evd_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CONSUMER_NAME = /^[a-z0-9][a-z0-9._:-]{2,127}$/u;
const OUTCOMES = new Set(["recorded", "duplicate"]);
const EVENT_EFFECTS = Object.freeze({
  "certificate.issued.v1": Object.freeze({
    state: "active", kind: "certificate-issued", componentScore: 100, terminal: false,
  }),
  "certificate.renewed.v1": Object.freeze({
    state: "active", kind: "certificate-renewed", componentScore: 100, terminal: false,
  }),
  "certificate.superseded.v1": Object.freeze({
    state: "superseded", kind: "certificate-superseded", componentScore: 100, terminal: true,
  }),
  "certificate.revoked.v1": Object.freeze({
    state: "revoked", kind: "certificate-revoked", componentScore: 0, terminal: true,
  }),
  "certificate.expired.v1": Object.freeze({
    state: "expired", kind: "certificate-expired", componentScore: 0, terminal: true,
  }),
});
const RECORD_SQL = `
  SELECT * FROM trust.record_certificate_lifecycle_evidence(
    $1, $2, $3, $4, $5, $6
  )
`;

export const CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY = Object.freeze({
  deliverySemantics: "at-least-once-delivery-exactly-once-trust-effect",
  acceptedEventTypes: Object.freeze(Object.keys(EVENT_EFFECTS)),
  evidenceType: "certificate",
  lifecycleAuthority: "signed-published-certificate-event",
  securityActionEligibility: false,
  causalParent: "certificate-lifecycle-event-causation-id",
});

export class CertificateLifecycleFeedbackError extends Error {
  constructor(reasonCode, options) {
    super("Certificate lifecycle trust feedback failed.", options);
    this.name = "CertificateLifecycleFeedbackError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new CertificateLifecycleFeedbackError(
    reasonCode,
    cause === undefined ? undefined : { cause },
  );
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function canonicalUtc(value) {
  if (typeof value !== "string" || !value.endsWith("Z")) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function evidenceIdFor(eventId) {
  const evidenceId = `evd_${eventId.slice(4)}`;
  if (!EVIDENCE_ID.test(evidenceId)) fail("CERTIFICATE_FEEDBACK_EVENT_INVALID");
  return evidenceId;
}

function normalizeVerifiedLifecycleEvent(event, verified) {
  const effect = EVENT_EFFECTS[event?.eventType];
  if (!effect
    || !TENANT_ID.test(event?.tenantId ?? "")
    || !SUBJECT_ID.test(event?.subjectId ?? "")
    || !CERTIFICATE_ID.test(event?.aggregateId ?? "")
    || !EVENT_ID.test(event?.eventId ?? "")
    || !CORRELATION_ID.test(event?.correlationId ?? "")
    || !canonicalUtc(event?.occurredAt)
    || event.payload?.certificateId !== event.aggregateId
    || event.payload?.state !== effect.state
    || verified?.tenantId !== event.tenantId
    || verified?.subjectId !== event.subjectId
    || verified?.eventId !== event.eventId
    || verified?.aggregateId !== event.aggregateId
    || verified?.eventType !== event.eventType
    || verified?.correlationId !== event.correlationId
    || verified?.causationId !== event.causationId
    || (event.eventType === "certificate.issued.v1"
      ? event.causationId !== null
      : !EVENT_ID.test(event.causationId ?? ""))) {
    fail("CERTIFICATE_FEEDBACK_EVENT_INVALID");
  }
  return deepFreeze({
    tenantId: event.tenantId,
    subjectId: event.subjectId,
    certificateId: event.aggregateId,
    evidenceId: evidenceIdFor(event.eventId),
    lifecycleEventId: event.eventId,
    causalParentEventId: event.causationId,
    correlationId: event.correlationId,
    evidenceType: "certificate",
    kind: effect.kind,
    componentScore: effect.componentScore,
    terminal: effect.terminal,
    securityActionEligible: false,
    observedAt: event.occurredAt,
  });
}

function mapResult(row, feedback) {
  const result = {
    applied: row?.applied,
    outcome: row?.outcome_code,
    tenantId: row?.tenant_id,
    subjectId: row?.subject_id,
    certificateId: row?.certificate_id,
    evidenceId: row?.evidence_id,
    lifecycleEventId: row?.lifecycle_event_id,
    causalParentEventId: row?.causal_parent_event_id,
    kind: row?.evidence_kind,
    componentScore: Number(row?.component_score),
    terminal: row?.terminal,
    securityActionEligible: row?.security_action_eligible,
    sourceActionId: row?.source_action_id ?? null,
  };
  if (typeof result.applied !== "boolean"
    || !OUTCOMES.has(result.outcome)
    || (result.outcome === "recorded") !== result.applied
    || result.tenantId !== feedback.tenantId
    || result.subjectId !== feedback.subjectId
    || result.certificateId !== feedback.certificateId
    || result.evidenceId !== feedback.evidenceId
    || result.lifecycleEventId !== feedback.lifecycleEventId
    || result.causalParentEventId !== feedback.causalParentEventId
    || result.kind !== feedback.kind
    || result.componentScore !== feedback.componentScore
    || result.terminal !== feedback.terminal
    || result.securityActionEligible !== false
    || (result.sourceActionId !== null && !ACTION_ID.test(result.sourceActionId))) {
    fail("CERTIFICATE_FEEDBACK_RESULT_INVALID");
  }
  return deepFreeze(result);
}

async function inConsumerTransaction(pool, operation, signal) {
  const client = await pool.connect();
  const query = (text, values) => client.query({ text, values, signal });
  try {
    await query("BEGIN");
    await query("SET LOCAL ROLE tenant_trust_certificate_feedback_consumer");
    const result = await operation(query);
    await query("COMMIT");
    return result;
  } catch (error) {
    try {
      await query("ROLLBACK");
    } catch {
      // Preserve the original feedback failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

export function createPostgresCertificateLifecycleFeedbackRepository({ pool, clock = () => new Date() } = {}) {
  if (!pool || typeof pool.connect !== "function" || typeof clock !== "function") {
    throw new TypeError("A PostgreSQL pool and clock are required.");
  }
  return Object.freeze({
    async consume({ consumerName, feedback, streamSequence, signedEventSha256, applyTrustEvidence }, { signal } = {}) {
      const processedAt = clock();
      if (!CONSUMER_NAME.test(consumerName ?? "")
        || !feedback
        || !TENANT_ID.test(feedback.tenantId ?? "")
        || !EVENT_ID.test(feedback.lifecycleEventId ?? "")
        || !Number.isSafeInteger(streamSequence)
        || streamSequence < 1
        || !SHA256.test(signedEventSha256 ?? "")
        || !(processedAt instanceof Date)
        || !Number.isFinite(processedAt.getTime())
        || typeof applyTrustEvidence !== "function") {
        fail("CERTIFICATE_FEEDBACK_REQUEST_INVALID");
      }
      return inConsumerTransaction(pool, async (query) => {
        const databaseResult = await query(RECORD_SQL, [
          consumerName,
          feedback.tenantId,
          feedback.lifecycleEventId,
          streamSequence,
          signedEventSha256,
          processedAt.toISOString(),
        ]);
        if (!databaseResult || !Array.isArray(databaseResult.rows)
          || databaseResult.rows.length !== 1) {
          fail("CERTIFICATE_FEEDBACK_RESULT_INVALID");
        }
        const result = mapResult(databaseResult.rows[0], feedback);
        if (result.applied) {
          await applyTrustEvidence({
            feedback,
            sourceActionId: result.sourceActionId,
            query,
            signal,
          });
        }
        return result;
      }, signal);
    },
  });
}

export function createCertificateLifecycleTrustFeedbackConsumer({
  consumerName,
  verifyEvent,
  repository,
  applyTrustEvidence,
} = {}) {
  if (!CONSUMER_NAME.test(consumerName ?? "")
    || typeof verifyEvent !== "function"
    || !repository
    || typeof repository.consume !== "function"
    || typeof applyTrustEvidence !== "function") {
    throw new TypeError(
      "A consumer name, certificate-event verifier, repository and trust-effect handler are required.",
    );
  }
  return Object.freeze({
    async consume({ event, streamSequence, expectedTenantId, resolvePublicKey, signal } = {}) {
      if (!Number.isSafeInteger(streamSequence) || streamSequence < 1) {
        fail("CERTIFICATE_FEEDBACK_DELIVERY_INVALID");
      }
      const verified = await verifyEvent({
        event,
        expectedTenantId,
        resolvePublicKey,
      });
      const feedback = normalizeVerifiedLifecycleEvent(event, verified);
      if (expectedTenantId !== undefined && feedback.tenantId !== expectedTenantId) {
        fail("CERTIFICATE_FEEDBACK_TENANT_MISMATCH");
      }
      const signedEventSha256 = createHash("sha256")
        .update(Buffer.from(canonicalizeJson(event), "utf8"))
        .digest("hex");
      const result = await repository.consume({
        consumerName,
        feedback,
        streamSequence,
        signedEventSha256,
        applyTrustEvidence,
      }, { signal });
      if (!result || typeof result.applied !== "boolean") {
        fail("CERTIFICATE_FEEDBACK_RESULT_INVALID");
      }
      return deepFreeze({ ...result, feedback });
    },
  });
}
