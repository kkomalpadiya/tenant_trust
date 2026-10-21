import assert from "node:assert/strict";
import { buildAuditCommitment } from "@tenant-trust/contracts/audit-commitments";
import { connectFabricAuditGatewayFromEnvironment } from "../apps/api/src/fabric-audit-gateway.mjs";
import { AuditVerificationError, createCausalAuditVerifier } from "../services/audit/src/index.mjs";

const ids = Object.freeze({
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789d1",
  issuer: "iss_018f1234-5678-7abc-8def-0123456789ab",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789d2",
  evidenceEvent: "evt_018f1234-5678-7abc-8def-0123456789d3",
  transition: "trn_018f1234-5678-7abc-8def-0123456789d4",
  policy: "pol_018f1234-5678-7abc-8def-0123456789d5",
  request: "req_018f1234-5678-7abc-8def-0123456789d6",
  decision: "dec_018f1234-5678-7abc-8def-0123456789d7",
  action: "act_018f1234-5678-7abc-8def-0123456789d8",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789d9",
});
const channelName = "tt-audit-alpha-v1";
const hash = "ab".repeat(32);

function envelope(eventSuffix, minute, eventType, aggregateId, payload, causationId = null, overrides = {}) {
  return Object.freeze({ schemaVersion: "1.0.0",eventId: `evt_018f1234-5678-7abc-8def-0123456789${eventSuffix}`,
    eventType,tenantId: ids.tenant,subjectId: ids.subject,aggregateId,correlationId: ids.correlation,causationId,
    idempotencyKey: `causal-audit-live:${eventType}:v1`,occurredAt: `2026-10-21T09:${minute}:00.000Z`,
    recordedAt: `2026-10-21T09:${minute}:01.000Z`,producer: { service: "causal-audit-verifier",instanceId: "verify-1" },
    payload,...overrides });
}

const certificate = envelope("da", "01", "certificate.issued.v1", ids.certificate, {
  certificateId: ids.certificate,issuerId: ids.issuer,serialNumber: "02AF".padEnd(32, "0"),fingerprintSha256: hash,
  state: "active",notBefore: "2026-10-21T09:01:00.000Z",notAfter: "2027-10-21T09:01:00.000Z",
  supersedesCertificateId: null,actorSubjectId: ids.subject,
}, null, { sourceAuthentication: { algorithm: "Ed25519",canonicalization: "tenant-trust-json-v1",
  keyId: "certificate-events:key-2026-01",signedContentSha256: hash,signatureBase64Url: "A".repeat(86) } });
const trust = envelope("db", "05", "trust.updated.v1", ids.transition, {
  transitionId: ids.transition,previousScore: 86,newScore: 62,previousBand: "trusted",newBand: "restricted",
  modelVersion: "1.0.0",configurationVersion: 3,evidenceIds: [ids.evidence],explanationHashSha256: hash,
}, ids.evidenceEvent);
const policy = envelope("dc", "06", "policy.activated.v1", ids.policy, {
  policyVersionId: ids.policy,bundleVersion: 3,bundleHashSha256: hash,state: "active",replacesPolicyVersionId: null,
}, trust.eventId);
const decision = envelope("dd", "07", "access.decided.v1", ids.decision, {
  decisionId: ids.decision,requestId: ids.request,certificateId: ids.certificate,trustTransitionId: ids.transition,
  trustScore: 62,policyVersionId: ids.policy,operation: "record:export",resourceType: "tenant-records",
  resourceIdHashSha256: hash,outcome: "DENY",reasonCodes: ["TRUST_BELOW_EXPORT_THRESHOLD"],stepUpProofIdHashSha256: null,
}, policy.eventId);
const action = envelope("de", "08", "security-action.requested.v1", ids.action, {
  actionId: ids.action,decisionId: ids.decision,actionType: "restrict-access",status: "requested",
  targetCertificateId: ids.certificate,reasonCode: "TRUST_RESTRICTED",
}, decision.eventId);

const client = await connectFabricAuditGatewayFromEnvironment();
try {
  const records = [];
  for (const event of [certificate,trust,policy,decision,action]) {
    const commitment = buildAuditCommitment({ channelName,event });
    const submission = await client.submitCommitment({ tenantId: ids.tenant,ledgerValue: commitment.ledgerValue });
    const status = await submission.waitForCommit();
    assert.equal(status.successful, true);
    records.push(Object.freeze({ tenantId: ids.tenant,eventId: event.eventId,channelName,event,
      canonicalPreimageJson: commitment.canonicalPreimageJson,ledgerKey: commitment.ledgerKey,
      ledgerValue: commitment.ledgerValue,deliveryStatus: "committed",transactionId: status.transactionId,
      validationCode: status.validationCode,blockNumber: Number(status.blockNumber) }));
  }
  const bundle = { tenantId: ids.tenant,correlationId: ids.correlation,records,
    evidenceAnchors: [{ transitionId: ids.transition,subjectId: ids.subject,evidenceId: ids.evidence,
      evidenceEventId: ids.evidenceEvent,evidenceCorrelationId: ids.correlation }] };
  const verifier = createCausalAuditVerifier({ loadBundle: async () => bundle,readCommitment: client.readCommitment });
  const result = await verifier.verify({ tenantId: ids.tenant,correlationId: ids.correlation });
  assert.equal(result.verified, true);
  assert.equal(result.commitmentCount, 5);
  assert.deepEqual(result.links, { evidence: 1,trustTransition: 1,policy: 1,decision: 1,certificate: 1,certificateAction: 1 });

  const tampered = { ...bundle,records: [...records] };
  tampered.records[1] = { ...tampered.records[1],event: { ...tampered.records[1].event,
    payload: { ...tampered.records[1].event.payload,newScore: 61 } } };
  await assert.rejects(createCausalAuditVerifier({ loadBundle: async () => tampered,readCommitment: client.readCommitment })
    .verify({ tenantId: ids.tenant,correlationId: ids.correlation }),
  (error) => error instanceof AuditVerificationError && error.reasonCode === "OFFCHAIN_COMMITMENT_MISMATCH");
  console.log("Causal audit verification passed: five off-chain records were recomputed, matched on-chain commitments, and formed a valid evidence-to-action chain; tampering was rejected.");
} finally {
  client.close();
}
