import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import {
  SecurityActionAuditError,
  buildSecurityActionAuditEvent,
  createPostgresSecurityActionAuditRepository,
  createPostgresSecurityActionAuditVerificationRepository,
  createSecurityActionAuditProjector,
  createSecurityActionAuditVerifier,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789a0",
  subject: "sub_018f1234-5678-7abc-8def-0123456789a1",
  admin: "sub_018f1234-5678-7abc-8def-0123456789a2",
  targetCertificate: "crt_018f1234-5678-7abc-8def-0123456789a3",
  replacementCertificate: "crt_018f1234-5678-7abc-8def-0123456789a4",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789a5",
  decision: "dec_018f1234-5678-7abc-8def-0123456789a6",
  transition: "trn_018f1234-5678-7abc-8def-0123456789a7",
  action: "act_018f1234-5678-7abc-8def-0123456789a8",
  recoveryAction: "act_018f1234-5678-7abc-8def-0123456789a9",
  authorization: "rca_018f1234-5678-7abc-8def-0123456789aa",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
  recoveryCorrelation: "cor_018f1234-5678-7abc-8def-0123456789ac",
  decisionEvent: "evt_018f1234-5678-7abc-8def-0123456789b0",
  trustEvent: "evt_018f1234-5678-7abc-8def-0123456789b1",
  certificateEvent: "evt_018f1234-5678-7abc-8def-0123456789b2",
  actionRequestedEvent: "evt_018f1234-5678-7abc-8def-0123456789b3",
  recoveryRequestedEvent: "evt_018f1234-5678-7abc-8def-0123456789b4",
  recoverySucceededEvent: "evt_018f1234-5678-7abc-8def-0123456789b5",
});
const hash = "ab".repeat(32);
const channelName = "tt-audit-alpha-v1";

function source(overrides = {}) {
  return Object.freeze({
    tenantId: ids.tenant,
    eventId: ids.actionRequestedEvent,
    actionId: ids.action,
    eventType: "security-action.requested.v1",
    status: "requested",
    attemptNumber: 0,
    decisionId: ids.decision,
    correlationId: ids.correlation,
    targetSubjectId: ids.subject,
    targetCertificateId: ids.targetCertificate,
    actionType: "restrict-access",
    authorityClass: "policy-quarantine",
    reasonCode: "TRUST_RESTRICTED",
    recoveryAuthorizationId: null,
    recoveryTrustTransitionId: null,
    authorizedBySubjectId: null,
    causeResolutionReference: null,
    externalReference: null,
    failureCode: null,
    occurredAt: "2026-10-23T08:00:00.000Z",
    recordedAt: "2026-10-23T08:00:00.100Z",
    causationEventId: ids.decisionEvent,
    certificateEventId: null,
    ...overrides,
  });
}

function envelope({ eventId, eventType, aggregateId, correlationId = ids.correlation, payload, subjectId = ids.subject }) {
  return Object.freeze({
    schemaVersion: "1.0.0",
    eventId,
    eventType,
    tenantId: ids.tenant,
    subjectId,
    aggregateId,
    correlationId,
    causationId: null,
    idempotencyKey: `security-action-audit-test:${eventId}`,
    occurredAt: "2026-10-23T07:59:00.000Z",
    recordedAt: "2026-10-23T07:59:00.100Z",
    producer: { service: "audit-test", instanceId: "test-1" },
    payload,
  });
}

function record(event, index) {
  const commitment = buildAuditCommitment({ channelName, event });
  return Object.freeze({
    tenantId: ids.tenant,
    eventId: event.eventId,
    channelName,
    event,
    canonicalPreimageJson: commitment.canonicalPreimageJson,
    ledgerKey: commitment.ledgerKey,
    ledgerValue: commitment.ledgerValue,
    deliveryStatus: "committed",
    transactionId: String(index).repeat(64),
    validationCode: 0,
    blockNumber: 100 + index,
  });
}

function fixture() {
  const decision = envelope({
    eventId: ids.decisionEvent,
    eventType: "access.decided.v1",
    aggregateId: ids.decision,
    payload: {
      decisionId: ids.decision,
      requestId: "req_018f1234-5678-7abc-8def-0123456789c0",
      certificateId: ids.targetCertificate,
      trustTransitionId: null,
      trustScore: 40,
      policyVersionId: "pol_018f1234-5678-7abc-8def-0123456789c1",
      operation: "record:export",
      resourceType: "tenant-records",
      resourceIdHashSha256: hash,
      outcome: "QUARANTINE",
      reasonCodes: ["TRUST_RESTRICTED"],
      stepUpProofIdHashSha256: null,
    },
  });
  const trust = envelope({
    eventId: ids.trustEvent,
    eventType: "trust.updated.v1",
    aggregateId: ids.transition,
    correlationId: ids.recoveryCorrelation,
    payload: {
      transitionId: ids.transition,
      previousScore: 60,
      newScore: 80,
      previousBand: "restricted",
      newBand: "trusted",
      modelVersion: "1.0.0",
      configurationVersion: 1,
      evidenceIds: ["evd_018f1234-5678-7abc-8def-0123456789c3"],
      explanationHashSha256: hash,
    },
  });
  const certificate = envelope({
    eventId: ids.certificateEvent,
    eventType: "certificate.issued.v1",
    aggregateId: ids.replacementCertificate,
    correlationId: ids.recoveryCorrelation,
    payload: {
      certificateId: ids.replacementCertificate,
      issuerId: ids.issuer,
      serialNumber: "01AF".padEnd(32, "0"),
      fingerprintSha256: hash,
      state: "active",
      notBefore: "2026-10-23T08:01:00.000Z",
      notAfter: "2027-10-23T08:01:00.000Z",
      supersedesCertificateId: null,
      actorSubjectId: ids.admin,
    },
    subjectId: ids.subject,
  });
  const signedCertificate = Object.freeze({
    ...certificate,
    sourceAuthentication: {
      algorithm: "Ed25519",
      canonicalization: "tenant-trust-json-v1",
      keyId: "certificate-events:key-2026-01",
      signedContentSha256: hash,
      signatureBase64Url: "A".repeat(86),
    },
  });
  const normal = source();
  const recoveryRequested = source({
    eventId: ids.recoveryRequestedEvent,
    actionId: ids.recoveryAction,
    decisionId: "dec_018f1234-5678-7abc-8def-0123456789c2",
    actionType: "issue-replacement-certificate",
    authorityClass: "recovery-authorization",
    reasonCode: "REPLACEMENT_ELIGIBLE",
    recoveryAuthorizationId: ids.authorization,
    recoveryTrustTransitionId: ids.transition,
    authorizedBySubjectId: ids.admin,
    causeResolutionReference: "case:resolved:123",
    causationEventId: ids.trustEvent,
  });
  const recoverySucceeded = source({
    eventId: ids.recoverySucceededEvent,
    actionId: ids.recoveryAction,
    eventType: "security-action.succeeded.v1",
    status: "succeeded",
    attemptNumber: 1,
    decisionId: recoveryRequested.decisionId,
    actionType: "issue-replacement-certificate",
    authorityClass: "recovery-authorization",
    reasonCode: "REPLACEMENT_ELIGIBLE",
    recoveryAuthorizationId: ids.authorization,
    recoveryTrustTransitionId: ids.transition,
    authorizedBySubjectId: ids.admin,
    causeResolutionReference: "case:resolved:123",
    externalReference: ids.replacementCertificate,
    causationEventId: ids.recoveryRequestedEvent,
    certificateEventId: ids.certificateEvent,
    occurredAt: "2026-10-23T08:02:00.000Z",
    recordedAt: "2026-10-23T08:02:00.100Z",
  });
  const expectations = [normal, recoveryRequested, recoverySucceeded];
  const records = [decision, trust, signedCertificate, ...expectations.map(buildSecurityActionAuditEvent)]
    .map((event, index) => record(event, index + 1));
  return { tenantId: ids.tenant, correlationId: ids.correlation, expectations, records };
}

function expectReason(reasonCode) {
  return (error) => error instanceof SecurityActionAuditError && error.reasonCode === reasonCode;
}

test("builds a canonical recovery action event with governance and certificate links", () => {
  const value = fixture().expectations[2];
  const event = buildSecurityActionAuditEvent(value);
  assert.equal(event.causationId, ids.recoveryRequestedEvent);
  assert.equal(event.payload.recoveryAuthorizationId, ids.authorization);
  assert.equal(event.payload.certificateEventId, ids.certificateEvent);
  assert.equal(event.payload.externalReference, ids.replacementCertificate);
});

test("projector writes the exact action event and canonical commitment", async () => {
  const expected = source();
  let written;
  const result = await createSecurityActionAuditProjector({
    repository: {
      loadNext: async () => expected,
      record: async (value) => {
        written = value;
        return { eventId: expected.eventId, status: "pending" };
      },
    },
    channelForTenant: async () => channelName,
  }).runOnce();
  assert.equal(result.status, "pending");
  assert.equal(written.event.eventId, expected.eventId);
  assert.equal(written.commitment.ledgerValue.recordType, "security-action");
});

test("projector refuses unresolved action causes and certificate outcomes", () => {
  assert.throws(() => buildSecurityActionAuditEvent(source({ causationEventId: null })),
    expectReason("ACTION_AUDIT_CAUSATION_PENDING"));
  assert.throws(() => buildSecurityActionAuditEvent(source({
    eventType: "security-action.succeeded.v1",
    status: "succeeded",
    attemptNumber: 1,
    actionType: "revoke-certificate",
    externalReference: ids.certificateEvent,
    certificateEventId: null,
  })), expectReason("ACTION_AUDIT_CERTIFICATE_EVENT_PENDING"));
});

test("verifier proves action, recovery, terminal and replacement-certificate links", async () => {
  const bundle = fixture();
  const ledger = new Map(bundle.records.map(({ ledgerValue }) => [ledgerValue.eventKeyHashSha256, ledgerValue]));
  const result = await createSecurityActionAuditVerifier({
    loadBundle: async () => bundle,
    readCommitment: async ({ eventKeyHashSha256 }) => ledger.get(eventKeyHashSha256),
  }).verify({ tenantId: ids.tenant, correlationId: ids.correlation });
  assert.deepEqual(result, {
    verified: true,
    tenantId: ids.tenant,
    correlationId: ids.correlation,
    actionEventCount: 3,
    recoveryLinks: 2,
    certificateLinks: 1,
  });
});

test("verifier detects a missing or mismatched action record", async (context) => {
  await context.test("missing", async () => {
    const bundle = fixture();
    bundle.records = bundle.records.filter(({ eventId }) => eventId !== ids.recoverySucceededEvent);
    await assert.rejects(createSecurityActionAuditVerifier({
      loadBundle: async () => bundle,
      readCommitment: async () => assert.fail("ledger must not be read for an incomplete source"),
    }).verify({ tenantId: ids.tenant, correlationId: ids.correlation }),
    expectReason("ACTION_AUDIT_EVENT_MISSING"));
  });
  await context.test("mismatched", async () => {
    const bundle = fixture();
    const index = bundle.records.findIndex(({ eventId }) => eventId === ids.actionRequestedEvent);
    const changed = { ...bundle.records[index].event, payload: {
      ...bundle.records[index].event.payload, reasonCode: "TRUST_SUSPENDED",
    } };
    bundle.records[index] = record(changed, 9);
    await assert.rejects(createSecurityActionAuditVerifier({
      loadBundle: async () => bundle,
      readCommitment: async () => assert.fail("ledger must not be read for a mismatched source"),
    }).verify({ tenantId: ids.tenant, correlationId: ids.correlation }),
    expectReason("ACTION_AUDIT_EVENT_MISMATCH"));
  });
});

test("verifier detects a ledger commitment mismatch", async () => {
  const bundle = fixture();
  await assert.rejects(createSecurityActionAuditVerifier({
    loadBundle: async () => bundle,
    readCommitment: async () => ({ ...bundle.records[0].ledgerValue,
      commitmentHashSha256: "cd".repeat(32) }),
  }).verify({ tenantId: ids.tenant, correlationId: ids.correlation }),
  expectReason("ACTION_AUDIT_LEDGER_MISMATCH"));
});

test("PostgreSQL adapters use only bounded projector and verifier functions", async () => {
  const calls = [];
  const expected = source();
  const row = {
    tenant_id: expected.tenantId,
    event_id: expected.eventId,
    action_id: expected.actionId,
    event_type: expected.eventType,
    event_status: expected.status,
    attempt_number: expected.attemptNumber,
    decision_id: expected.decisionId,
    correlation_id: expected.correlationId,
    target_subject_id: expected.targetSubjectId,
    target_certificate_id: expected.targetCertificateId,
    action_type: expected.actionType,
    authority_class: expected.authorityClass,
    reason_code: expected.reasonCode,
    recovery_authorization_id: null,
    recovery_trust_transition_id: null,
    recovery_authorized_by_subject_id: null,
    cause_resolution_reference: null,
    external_reference: null,
    failure_code: null,
    occurred_at: expected.occurredAt,
    recorded_at: expected.recordedAt,
    causation_event_id: expected.causationEventId,
    certificate_event_id: null,
  };
  const repository = createPostgresSecurityActionAuditRepository({
    clock: () => new Date("2026-10-23T08:03:00.000Z"),
    query: async (sql) => {
      calls.push(sql);
      if (sql.includes("get_pending")) return { rows: [row] };
      return { rows: [{ event_id: expected.eventId, status: "pending" }] };
    },
  });
  const loaded = await repository.loadNext();
  const event = buildSecurityActionAuditEvent(loaded);
  await repository.record({ source: loaded, channelName, event,
    commitment: buildAuditCommitment({ channelName, event }) });
  assert.match(calls[0], /get_pending_security_action_audit_event/u);
  assert.match(calls[1], /record_security_action_audit_commitment/u);

  const bundle = fixture();
  const verifyCalls = [];
  const verifierRepository = createPostgresSecurityActionAuditVerificationRepository({ query: async (sql) => {
    verifyCalls.push(sql);
    if (sql.includes("expectations")) return { rows: [row] };
    const first = bundle.records.find(({ eventId }) => eventId === expected.eventId);
    return { rows: [{ tenant_id: first.tenantId,event_id: first.eventId,channel_name: first.channelName,
      event_document: first.event,canonical_preimage_json: first.canonicalPreimageJson,
      ledger_key: first.ledgerKey,ledger_value: first.ledgerValue,delivery_status: first.deliveryStatus,
      transaction_id: first.transactionId,validation_code: first.validationCode,block_number: first.blockNumber }] };
  } });
  const loadedBundle = await verifierRepository.loadBundle({ tenantId: ids.tenant, correlationId: ids.correlation });
  assert.equal(loadedBundle.expectations.length, 1);
  assert.equal(loadedBundle.records.length, 1);
  assert.equal(verifyCalls.length, 2);
});
