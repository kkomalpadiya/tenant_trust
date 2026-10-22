import assert from "node:assert/strict";
import test from "node:test";

import {
  CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY,
  CertificateLifecycleFeedbackError,
  createCertificateLifecycleTrustFeedbackConsumer,
  createPostgresCertificateLifecycleFeedbackRepository,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ac",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ad",
  event: "evt_018f1234-5678-7abc-8def-0123456789ae",
  cause: "evt_018f1234-5678-7abc-8def-0123456789af",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789b0",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789ae",
  action: "act_018f1234-5678-7abc-8def-0123456789b1",
});

const effects = Object.freeze({
  "certificate.issued.v1": { state: "active", kind: "certificate-issued", score: 100, terminal: false },
  "certificate.renewed.v1": { state: "active", kind: "certificate-renewed", score: 100, terminal: false },
  "certificate.superseded.v1": { state: "superseded", kind: "certificate-superseded", score: 100, terminal: true },
  "certificate.revoked.v1": { state: "revoked", kind: "certificate-revoked", score: 0, terminal: true },
  "certificate.expired.v1": { state: "expired", kind: "certificate-expired", score: 0, terminal: true },
});

function lifecycleEvent(eventType = "certificate.revoked.v1", overrides = {}) {
  const effect = effects[eventType];
  return {
    schemaVersion: "1.0.0",
    eventId: ids.event,
    eventType,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    aggregateId: ids.certificate,
    correlationId: ids.correlation,
    causationId: eventType === "certificate.issued.v1" ? null : ids.cause,
    idempotencyKey: "certificate-feedback-test",
    occurredAt: "2026-10-22T10:00:00.000Z",
    recordedAt: "2026-10-22T10:00:00.100Z",
    producer: { service: "certificate-events", instanceId: "test" },
    payload: {
      certificateId: ids.certificate,
      state: effect.state,
    },
    sourceAuthentication: {
      algorithm: "Ed25519",
      canonicalization: "tenant-trust-json-v1",
      keyId: "certificate-events:test-key",
      signedContentSha256: "a".repeat(64),
      signatureBase64Url: "A".repeat(86),
    },
    ...overrides,
  };
}

function databaseRow(feedback, overrides = {}) {
  return {
    applied: true,
    outcome_code: "recorded",
    tenant_id: feedback.tenantId,
    subject_id: feedback.subjectId,
    certificate_id: feedback.certificateId,
    evidence_id: feedback.evidenceId,
    lifecycle_event_id: feedback.lifecycleEventId,
    causal_parent_event_id: feedback.causalParentEventId,
    evidence_kind: feedback.kind,
    component_score: String(feedback.componentScore),
    terminal: feedback.terminal,
    security_action_eligible: false,
    source_action_id: feedback.kind === "certificate-revoked" ? ids.action : null,
    ...overrides,
  };
}

function poolWith(handler) {
  const calls = [];
  let released = false;
  const client = {
    async query(configuration) {
      calls.push(configuration);
      return handler(configuration, calls.length);
    },
    release() { released = true; },
  };
  return {
    calls,
    get released() { return released; },
    async connect() { return client; },
  };
}

test("publishes an immutable non-recursive certificate feedback policy", () => {
  assert.equal(CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY.securityActionEligibility, false);
  assert.equal(CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY.evidenceType, "certificate");
  assert.deepEqual(
    CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY.acceptedEventTypes,
    Object.keys(effects),
  );
  assert.ok(Object.isFrozen(CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY));
  assert.ok(Object.isFrozen(CERTIFICATE_LIFECYCLE_FEEDBACK_POLICY.acceptedEventTypes));
});

test("maps every signed lifecycle outcome to deterministic certificate evidence", async () => {
  for (const [eventType, effect] of Object.entries(effects)) {
    let received;
    const event = lifecycleEvent(eventType);
    const consumer = createCertificateLifecycleTrustFeedbackConsumer({
      consumerName: "trust-feedback.test",
      verifyEvent: async ({ event: delivered }) => delivered,
      repository: {
        async consume(input) {
          received = input;
          return {
            applied: true,
            outcome: "recorded",
            sourceActionId: eventType === "certificate.revoked.v1" ? ids.action : null,
          };
        },
      },
      applyTrustEvidence: async () => {},
    });

    const result = await consumer.consume({
      event,
      streamSequence: 42,
      expectedTenantId: ids.tenant,
      resolvePublicKey: () => "test-key",
    });
    assert.equal(received.feedback.evidenceId, ids.evidence);
    assert.equal(received.feedback.causalParentEventId, event.causationId);
    assert.equal(received.feedback.kind, effect.kind);
    assert.equal(received.feedback.componentScore, effect.score);
    assert.equal(received.feedback.terminal, effect.terminal);
    assert.equal(received.feedback.securityActionEligible, false);
    assert.match(received.signedEventSha256, /^[0-9a-f]{64}$/u);
    assert.ok(Object.isFrozen(result.feedback));
  }
});

test("verifies the event before any durable trust work", async () => {
  const failure = new Error("signature invalid");
  let persisted = false;
  const consumer = createCertificateLifecycleTrustFeedbackConsumer({
    consumerName: "trust-feedback.test",
    verifyEvent: async () => { throw failure; },
    repository: { consume: async () => { persisted = true; } },
    applyTrustEvidence: async () => {},
  });
  await assert.rejects(consumer.consume({
    event: lifecycleEvent(),
    streamSequence: 42,
    expectedTenantId: ids.tenant,
  }), failure);
  assert.equal(persisted, false);
});

test("fails closed on a verified event whose target binding changed", async () => {
  const event = lifecycleEvent();
  const consumer = createCertificateLifecycleTrustFeedbackConsumer({
    consumerName: "trust-feedback.test",
    verifyEvent: async () => ({ ...event, subjectId: "sub_018f1234-5678-7abc-8def-0123456789b2" }),
    repository: { consume: async () => assert.fail("invalid binding reached persistence") },
    applyTrustEvidence: async () => {},
  });
  await assert.rejects(
    consumer.consume({ event, streamSequence: 42, expectedTenantId: ids.tenant }),
    (error) => error instanceof CertificateLifecycleFeedbackError
      && error.reasonCode === "CERTIFICATE_FEEDBACK_EVENT_INVALID",
  );
});

test("PostgreSQL repository records and applies one trust effect in one transaction", async () => {
  const feedback = {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    certificateId: ids.certificate,
    evidenceId: ids.evidence,
    lifecycleEventId: ids.event,
    causalParentEventId: ids.cause,
    kind: "certificate-revoked",
    componentScore: 0,
    terminal: true,
  };
  const pool = poolWith(async ({ text }) => (
    text.includes("record_certificate_lifecycle_evidence")
      ? { rows: [databaseRow(feedback)] }
      : { rows: [] }
  ));
  let effectQuery;
  const repository = createPostgresCertificateLifecycleFeedbackRepository({
    pool,
    clock: () => new Date("2026-10-22T10:00:01.000Z"),
  });
  const result = await repository.consume({
    consumerName: "trust-feedback.test",
    feedback,
    streamSequence: 42,
    signedEventSha256: "b".repeat(64),
    async applyTrustEvidence({ feedback: applied, sourceActionId, query }) {
      assert.equal(applied, feedback);
      assert.equal(sourceActionId, ids.action);
      effectQuery = query;
    },
  });

  assert.equal(result.applied, true);
  assert.equal(result.sourceActionId, ids.action);
  assert.equal(typeof effectQuery, "function");
  assert.deepEqual(pool.calls.map(({ text }) => text.trim()), [
    "BEGIN",
    "SET LOCAL ROLE tenant_trust_certificate_feedback_consumer",
    pool.calls[2].text.trim(),
    "COMMIT",
  ]);
  assert.deepEqual(pool.calls[2].values, [
    "trust-feedback.test", ids.tenant, ids.event, 42, "b".repeat(64),
    "2026-10-22T10:00:01.000Z",
  ]);
  assert.equal(pool.released, true);
});

test("a duplicate lifecycle event never applies a second trust effect", async () => {
  const feedback = {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    certificateId: ids.certificate,
    evidenceId: ids.evidence,
    lifecycleEventId: ids.event,
    causalParentEventId: ids.cause,
    kind: "certificate-revoked",
    componentScore: 0,
    terminal: true,
  };
  const pool = poolWith(async ({ text }) => (
    text.includes("record_certificate_lifecycle_evidence")
      ? { rows: [databaseRow(feedback, { applied: false, outcome_code: "duplicate" })] }
      : { rows: [] }
  ));
  let applied = false;
  const repository = createPostgresCertificateLifecycleFeedbackRepository({ pool });
  const result = await repository.consume({
    consumerName: "trust-feedback.test",
    feedback,
    streamSequence: 42,
    signedEventSha256: "b".repeat(64),
    applyTrustEvidence: async () => { applied = true; },
  });
  assert.equal(result.applied, false);
  assert.equal(result.outcome, "duplicate");
  assert.equal(applied, false);
});

test("a failed trust effect rolls back its evidence receipt for safe retry", async () => {
  const feedback = {
    tenantId: ids.tenant,
    subjectId: ids.subject,
    certificateId: ids.certificate,
    evidenceId: ids.evidence,
    lifecycleEventId: ids.event,
    causalParentEventId: ids.cause,
    kind: "certificate-revoked",
    componentScore: 0,
    terminal: true,
  };
  const pool = poolWith(async ({ text }) => (
    text.includes("record_certificate_lifecycle_evidence")
      ? { rows: [databaseRow(feedback)] }
      : { rows: [] }
  ));
  const failure = new Error("trust update failed");
  const repository = createPostgresCertificateLifecycleFeedbackRepository({ pool });
  await assert.rejects(repository.consume({
    consumerName: "trust-feedback.test",
    feedback,
    streamSequence: 42,
    signedEventSha256: "b".repeat(64),
    applyTrustEvidence: async () => { throw failure; },
  }), failure);
  assert.equal(pool.calls.at(-1).text, "ROLLBACK");
  assert.equal(pool.released, true);
});
