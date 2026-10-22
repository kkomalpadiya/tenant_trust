import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import {
  AuditVerificationError,
  createCausalAuditVerifier,
  createPostgresCausalAuditVerificationRepository,
} from "../src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789ab",
  evidenceEvent: "evt_018f1234-5678-7abc-8def-000000000004",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  policy: "pol_018f1234-5678-7abc-8def-0123456789ab",
  request: "req_018f1234-5678-7abc-8def-0123456789ab",
  decision: "dec_018f1234-5678-7abc-8def-0123456789ab",
  action: "act_018f1234-5678-7abc-8def-0123456789ab",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
});
const hash = "ab".repeat(32);

function envelope(number, eventType, aggregateId, payload, overrides = {}) {
  return Object.freeze({
    schemaVersion: "1.0.0",
    eventId: `evt_018f1234-5678-7abc-8def-${String(number).padStart(12, "0")}`,
    eventType,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    aggregateId,
    correlationId: ids.correlation,
    causationId: null,
    idempotencyKey: `causal-verification:${eventType}:${number}`,
    occurredAt: `2026-10-21T08:${String(number).padStart(2, "0")}:00.000Z`,
    recordedAt: `2026-10-21T08:${String(number).padStart(2, "0")}:01.000Z`,
    producer: { service: "audit-verification-test",instanceId: "test-1" },
    payload,
    ...overrides,
  });
}

function fixture() {
  const certificate = envelope(1, "certificate.issued.v1", ids.certificate, {
    certificateId: ids.certificate,issuerId: ids.issuer,serialNumber: "01AF".padEnd(32, "0"),
    fingerprintSha256: hash,state: "active",notBefore: "2026-10-21T08:01:00.000Z",
    notAfter: "2027-10-21T08:01:00.000Z",supersedesCertificateId: null,actorSubjectId: ids.subject,
  }, { sourceAuthentication: { algorithm: "Ed25519",canonicalization: "tenant-trust-json-v1",
    keyId: "certificate-events:key-2026-01",signedContentSha256: hash,signatureBase64Url: "A".repeat(86) } });
  const trust = envelope(5, "trust.updated.v1", ids.transition, {
    transitionId: ids.transition,previousScore: 86,newScore: 62,previousBand: "trusted",newBand: "restricted",
    modelVersion: "1.0.0",configurationVersion: 3,evidenceIds: [ids.evidence],explanationHashSha256: hash,
  }, { causationId: ids.evidenceEvent });
  const policy = envelope(6, "policy.activated.v1", ids.policy, {
    policyVersionId: ids.policy,bundleVersion: 3,bundleHashSha256: hash,state: "active",replacesPolicyVersionId: null,
  }, { causationId: trust.eventId });
  const decision = envelope(7, "access.decided.v1", ids.decision, {
    decisionId: ids.decision,requestId: ids.request,certificateId: ids.certificate,trustTransitionId: ids.transition,
    trustScore: 62,policyVersionId: ids.policy,operation: "record:export",resourceType: "tenant-records",
    resourceIdHashSha256: hash,outcome: "DENY",reasonCodes: ["TRUST_BELOW_EXPORT_THRESHOLD"],
    stepUpProofIdHashSha256: null,
  }, { causationId: policy.eventId });
  const action = envelope(8, "security-action.requested.v1", ids.action, {
    actionId: ids.action,decisionId: ids.decision,actionType: "restrict-access",status: "requested",
    targetCertificateId: ids.certificate,reasonCode: "TRUST_RESTRICTED",
  }, { causationId: decision.eventId });
  const events = [certificate,trust,policy,decision,action];
  const records = events.map((event, index) => {
    const commitment = buildAuditCommitment({ channelName: "tt-audit-alpha-v1",event });
    return Object.freeze({ tenantId: ids.tenant,eventId: event.eventId,channelName: "tt-audit-alpha-v1",event,
      canonicalPreimageJson: commitment.canonicalPreimageJson,ledgerKey: commitment.ledgerKey,
      ledgerValue: commitment.ledgerValue,deliveryStatus: "committed",transactionId: String(index + 1).repeat(64),
      validationCode: 0,blockNumber: 40 + index });
  });
  const evidenceAnchors = [Object.freeze({ transitionId: ids.transition,subjectId: ids.subject,
    evidenceId: ids.evidence,evidenceEventId: ids.evidenceEvent,evidenceCorrelationId: ids.correlation })];
  return { tenantId: ids.tenant,correlationId: ids.correlation,records,evidenceAnchors };
}

function verifier(bundle, readCommitment = async ({ eventKeyHashSha256 }) =>
  bundle.records.find(({ ledgerValue }) => ledgerValue.eventKeyHashSha256 === eventKeyHashSha256)?.ledgerValue) {
  return createCausalAuditVerifier({ loadBundle: async () => bundle,readCommitment });
}

function expectReason(reasonCode) {
  return (error) => error instanceof AuditVerificationError && error.reasonCode === reasonCode;
}

test("recomputes all commitments and verifies the complete causal graph", async () => {
  const result = await verifier(fixture()).verify({ tenantId: ids.tenant,correlationId: ids.correlation });
  assert.deepEqual({ verified: result.verified,eventCount: result.eventCount,commitmentCount: result.commitmentCount,
    links: result.links }, { verified: true,eventCount: 5,commitmentCount: 5,
    links: { evidence: 1,trustTransition: 1,policy: 1,decision: 1,certificate: 1,certificateAction: 1 } });
  assert.equal(result.events.every(({ transactionId,blockNumber }) => transactionId.length === 64 && blockNumber >= 40), true);
});

test("rejects a changed off-chain event even when stored hashes remain unchanged", async () => {
  const bundle = fixture();
  bundle.records[1] = { ...bundle.records[1],event: { ...bundle.records[1].event,
    payload: { ...bundle.records[1].event.payload,newScore: 61 } } };
  await assert.rejects(verifier(bundle).verify({ tenantId: ids.tenant,correlationId: ids.correlation }),
    expectReason("OFFCHAIN_COMMITMENT_MISMATCH"));
});

test("rejects coordinated off-chain tampering after local commitments are recomputed", async () => {
  const bundle = fixture();
  const ledgerByKey = new Map(bundle.records.map(({ ledgerValue }) => [ledgerValue.eventKeyHashSha256,ledgerValue]));
  bundle.records[1] = rebuild(bundle.records[1], { newScore: 61 });
  await assert.rejects(verifier(bundle, async ({ eventKeyHashSha256 }) => ledgerByKey.get(eventKeyHashSha256))
    .verify({ tenantId: ids.tenant,correlationId: ids.correlation }), expectReason("LEDGER_COMMITMENT_MISMATCH"));
});

test("rejects a ledger value that does not match the recomputed commitment", async () => {
  const bundle = fixture();
  await assert.rejects(verifier(bundle, async () => ({ ...bundle.records[0].ledgerValue,
    commitmentHashSha256: "cd".repeat(32) })).verify({ tenantId: ids.tenant,correlationId: ids.correlation }),
  expectReason("LEDGER_COMMITMENT_MISMATCH"));
});

test("rejects records that have not received successful durable commit metadata", async () => {
  const bundle = fixture();
  bundle.records[0] = { ...bundle.records[0],deliveryStatus: "submitted",validationCode: null,blockNumber: null };
  await assert.rejects(verifier(bundle).verify({ tenantId: ids.tenant,correlationId: ids.correlation }),
    expectReason("AUDIT_DELIVERY_NOT_COMMITTED"));
});

test("rejects broken evidence, trust, policy, decision, and certificate-action links", async (context) => {
  const cases = [
    ["evidence", "EVIDENCE_LINK_INVALID", (bundle) => { bundle.evidenceAnchors[0] = { ...bundle.evidenceAnchors[0],evidenceId: "evd_018f1234-5678-7abc-8def-0123456789ac" }; }],
    ["trust", "TRUST_TRANSITION_LINK_INVALID", (bundle) => { bundle.records[3] = rebuild(bundle.records[3], { trustScore: 61 }); }],
    ["policy", "POLICY_LINK_INVALID", (bundle) => { bundle.records[3] = rebuild(bundle.records[3], { policyVersionId: "pol_018f1234-5678-7abc-8def-0123456789ac" }); }],
    ["decision", "DECISION_ACTION_LINK_INVALID", (bundle) => { bundle.records[4] = rebuild(bundle.records[4], { decisionId: "dec_018f1234-5678-7abc-8def-0123456789ac" }); }],
    ["certificate action", "CERTIFICATE_ACTION_LINK_INVALID", (bundle) => { bundle.records[4] = rebuild(bundle.records[4], { targetCertificateId: "crt_018f1234-5678-7abc-8def-0123456789ac" }); }],
  ];
  for (const [name,reasonCode,change] of cases) {
    await context.test(name, async () => {
      const bundle = fixture();
      change(bundle);
      await assert.rejects(verifier(bundle).verify({ tenantId: ids.tenant,correlationId: ids.correlation }), expectReason(reasonCode));
    });
  }
});

function rebuild(record, payloadChanges) {
  const event = { ...record.event,payload: { ...record.event.payload,...payloadChanges } };
  const commitment = buildAuditCommitment({ channelName: record.channelName,event });
  return { ...record,event,canonicalPreimageJson: commitment.canonicalPreimageJson,
    ledgerKey: commitment.ledgerKey,ledgerValue: commitment.ledgerValue };
}

test("PostgreSQL adapter reads only the two bounded verifier functions", async () => {
  const source = fixture();
  const sql = [];
  const rows = source.records.map((record) => ({ tenant_id: record.tenantId,event_id: record.eventId,
    channel_name: record.channelName,event_document: record.event,canonical_preimage_json: record.canonicalPreimageJson,
    ledger_key: record.ledgerKey,ledger_value: record.ledgerValue,delivery_status: record.deliveryStatus,
    transaction_id: record.transactionId,validation_code: String(record.validationCode),block_number: String(record.blockNumber) }));
  const anchors = source.evidenceAnchors.map((anchor) => ({ transition_id: anchor.transitionId,subject_id: anchor.subjectId,
    evidence_id: anchor.evidenceId,evidence_event_id: anchor.evidenceEventId,evidence_correlation_id: anchor.evidenceCorrelationId }));
  const repository = createPostgresCausalAuditVerificationRepository({ query: async (text) => {
    sql.push(text);
    return { rows: text.includes("evidence_anchors") ? anchors : rows };
  } });
  const bundle = await repository.loadBundle({ tenantId: ids.tenant,correlationId: ids.correlation });
  assert.equal(bundle.records[0].blockNumber, 40);
  assert.equal(bundle.evidenceAnchors[0].transitionId, ids.transition);
  assert.deepEqual(sql, [
    "SELECT * FROM audit.list_fabric_causal_verification_records($1,$2)",
    "SELECT * FROM audit.list_fabric_causal_evidence_anchors($1,$2)",
  ]);
});
