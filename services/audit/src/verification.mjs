import { isDeepStrictEqual } from "node:util";
import { buildAuditCommitment, verifyAuditCommitment } from "@tenant-trust/contracts/audit-commitments";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CHANNEL = /^tt-audit-[a-z0-9-]+-v[1-9][0-9]*$/u;
const RECORD_FIELDS = ["blockNumber","canonicalPreimageJson","channelName","deliveryStatus","event","eventId",
  "ledgerKey","ledgerValue","tenantId","transactionId","validationCode"];
const ANCHOR_FIELDS = ["evidenceCorrelationId","evidenceEventId","evidenceId","subjectId","transitionId"];

export class AuditVerificationError extends Error {
  constructor(reasonCode, options) {
    super("Causal audit verification failed.", options);
    this.name = "AuditVerificationError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new AuditVerificationError(reasonCode, cause === undefined ? undefined : { cause });
}

function plain(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactFields(value, fields, reasonCode) {
  if (!plain(value) || !isDeepStrictEqual(Object.keys(value).sort(), fields)) fail(reasonCode);
}

function recordFromRow(row) {
  const value = {
    tenantId: row.tenant_id,
    eventId: row.event_id,
    channelName: row.channel_name,
    event: row.event_document,
    canonicalPreimageJson: row.canonical_preimage_json,
    ledgerKey: row.ledger_key,
    ledgerValue: row.ledger_value,
    deliveryStatus: row.delivery_status,
    transactionId: row.transaction_id,
    validationCode: row.validation_code === null ? null : Number(row.validation_code),
    blockNumber: row.block_number === null ? null : Number(row.block_number),
  };
  exactFields(value, RECORD_FIELDS, "VERIFICATION_SOURCE_INVALID");
  return Object.freeze(value);
}

function anchorFromRow(row) {
  const value = {
    transitionId: row.transition_id,
    subjectId: row.subject_id,
    evidenceId: row.evidence_id,
    evidenceEventId: row.evidence_event_id,
    evidenceCorrelationId: row.evidence_correlation_id,
  };
  exactFields(value, ANCHOR_FIELDS, "VERIFICATION_SOURCE_INVALID");
  return Object.freeze(value);
}

export function createPostgresCausalAuditVerificationRepository({ query } = {}) {
  if (typeof query !== "function") throw new TypeError("A verifier-role PostgreSQL query function is required.");
  return Object.freeze({
    async loadBundle({ tenantId, correlationId }, { signal } = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !CORRELATION_ID.test(correlationId ?? "")) {
        throw new TypeError("Canonical tenantId and correlationId values are required.");
      }
      const [recordResult, anchorResult] = await Promise.all([
        query("SELECT * FROM audit.list_fabric_causal_verification_records($1,$2)", [tenantId,correlationId], { signal }),
        query("SELECT * FROM audit.list_fabric_causal_evidence_anchors($1,$2)", [tenantId,correlationId], { signal }),
      ]);
      if (!Array.isArray(recordResult?.rows) || !Array.isArray(anchorResult?.rows)) fail("VERIFICATION_SOURCE_INVALID");
      return Object.freeze({ tenantId,correlationId,
        records: Object.freeze(recordResult.rows.map(recordFromRow)),
        evidenceAnchors: Object.freeze(anchorResult.rows.map(anchorFromRow)) });
    },
  });
}

function validateDurableRecord(record, tenantId, correlationId) {
  exactFields(record, RECORD_FIELDS, "VERIFICATION_SOURCE_INVALID");
  if (record.tenantId !== tenantId || record.eventId !== record.event?.eventId
      || record.event?.tenantId !== tenantId || record.event?.correlationId !== correlationId
      || !EVENT_ID.test(record.eventId ?? "") || !CHANNEL.test(record.channelName ?? "")
      || record.deliveryStatus !== "committed" || !SHA256.test(record.transactionId ?? "")
      || record.validationCode !== 0 || !Number.isSafeInteger(record.blockNumber) || record.blockNumber < 0) {
    fail(record.deliveryStatus === "committed" ? "VERIFICATION_SOURCE_INVALID" : "AUDIT_DELIVERY_NOT_COMMITTED");
  }
  let expected;
  try {
    expected = buildAuditCommitment({ channelName: record.channelName,event: record.event });
  } catch (error) {
    fail("OFFCHAIN_COMMITMENT_MISMATCH", error);
  }
  if (record.canonicalPreimageJson !== expected.canonicalPreimageJson
      || record.ledgerKey !== expected.ledgerKey
      || !isDeepStrictEqual(record.ledgerValue, expected.ledgerValue)
      || !verifyAuditCommitment({ channelName: record.channelName,event: record.event,
        ledgerKey: record.ledgerKey,ledgerValue: record.ledgerValue })) fail("OFFCHAIN_COMMITMENT_MISMATCH");
  return expected;
}

function oneBy(events, predicate, reasonCode) {
  const matches = events.filter(predicate);
  if (matches.length !== 1) fail(reasonCode);
  return matches[0];
}

function verifyLinks(records, evidenceAnchors) {
  const events = records.map(({ event }) => event);
  const eventById = new Map();
  for (const event of events) {
    if (eventById.has(event.eventId)) fail("DUPLICATE_EVENT_ID");
    eventById.set(event.eventId, event);
  }
  const evidenceEventIds = new Set();
  for (const anchor of evidenceAnchors) {
    exactFields(anchor, ANCHOR_FIELDS, "EVIDENCE_LINK_INVALID");
    if (!EVENT_ID.test(anchor.evidenceEventId ?? "")) fail("EVIDENCE_LINK_INVALID");
    evidenceEventIds.add(anchor.evidenceEventId);
  }
  for (const event of events) {
    if (event.causationId !== null && !eventById.has(event.causationId) && !evidenceEventIds.has(event.causationId)) {
      fail("CAUSATION_LINK_MISSING");
    }
    const cause = eventById.get(event.causationId);
    if (cause && Date.parse(cause.occurredAt) > Date.parse(event.occurredAt)) fail("CAUSATION_TIME_INVALID");
  }

  let evidenceLinks = 0;
  const trustEvents = events.filter(({ eventType }) => eventType === "trust.updated.v1");
  for (const trust of trustEvents) {
    const anchors = evidenceAnchors.filter(({ transitionId }) => transitionId === trust.payload.transitionId);
    const expected = [...trust.payload.evidenceIds].sort();
    const actual = anchors.map(({ evidenceId }) => evidenceId).sort();
    if (!isDeepStrictEqual(actual, expected)
        || anchors.some(({ subjectId }) => subjectId !== trust.subjectId)
        || !anchors.some(({ evidenceEventId }) => evidenceEventId === trust.causationId)) {
      fail("EVIDENCE_LINK_INVALID");
    }
    evidenceLinks += anchors.length;
  }

  let trustLinks = 0;
  let policyLinks = 0;
  let certificateLinks = 0;
  const decisions = events.filter(({ eventType }) => eventType === "access.decided.v1");
  for (const decision of decisions) {
    if (decision.payload.trustTransitionId !== null) {
      const trust = oneBy(trustEvents, (event) => event.payload.transitionId === decision.payload.trustTransitionId,
        "TRUST_TRANSITION_LINK_INVALID");
      if (trust.subjectId !== decision.subjectId || trust.payload.newScore !== decision.payload.trustScore) {
        fail("TRUST_TRANSITION_LINK_INVALID");
      }
      if (Date.parse(trust.occurredAt) > Date.parse(decision.occurredAt)) fail("TRUST_TRANSITION_LINK_INVALID");
      trustLinks += 1;
    }
    const policy = oneBy(events, (event) => event.eventType === "policy.activated.v1"
      && event.payload.policyVersionId === decision.payload.policyVersionId
      && event.payload.state === "active", "POLICY_LINK_INVALID");
    if (Date.parse(policy.occurredAt) > Date.parse(decision.occurredAt)) fail("POLICY_LINK_INVALID");
    policyLinks += 1;
    const certificate = oneBy(events, (event) => event.eventType.startsWith("certificate.")
      && event.payload.certificateId === decision.payload.certificateId
      && event.payload.state === "active", "CERTIFICATE_LINK_INVALID");
    if (certificate.subjectId !== decision.subjectId) fail("CERTIFICATE_LINK_INVALID");
    if (Date.parse(certificate.occurredAt) > Date.parse(decision.occurredAt)) fail("CERTIFICATE_LINK_INVALID");
    certificateLinks += 1;
  }

  let decisionLinks = 0;
  let certificateActionLinks = 0;
  for (const action of events.filter(({ eventType }) => eventType.startsWith("security-action."))) {
    const decision = oneBy(decisions, (event) => event.payload.decisionId === action.payload.decisionId,
      "DECISION_ACTION_LINK_INVALID");
    if (action.causationId !== decision.eventId || action.subjectId !== decision.subjectId) fail("DECISION_ACTION_LINK_INVALID");
    decisionLinks += 1;
    if (action.payload.targetCertificateId !== null) {
      if (action.payload.targetCertificateId !== decision.payload.certificateId) fail("CERTIFICATE_ACTION_LINK_INVALID");
      oneBy(events, (event) => event.eventType.startsWith("certificate.")
        && event.payload.certificateId === action.payload.targetCertificateId, "CERTIFICATE_ACTION_LINK_INVALID");
      certificateActionLinks += 1;
    }
  }
  if (evidenceLinks === 0 || trustLinks === 0 || policyLinks === 0 || decisionLinks === 0 || certificateActionLinks === 0) {
    fail("CAUSAL_CHAIN_INCOMPLETE");
  }
  return Object.freeze({ evidence: evidenceLinks,trustTransition: trustLinks,policy: policyLinks,
    decision: decisionLinks,certificate: certificateLinks,certificateAction: certificateActionLinks });
}

export function createCausalAuditVerifier({ loadBundle, readCommitment } = {}) {
  if (typeof loadBundle !== "function" || typeof readCommitment !== "function") {
    throw new TypeError("Off-chain audit bundle and Fabric commitment readers are required.");
  }
  return Object.freeze({
    async verify({ tenantId,correlationId }, options) {
      if (!TENANT_ID.test(tenantId ?? "") || !CORRELATION_ID.test(correlationId ?? "")) {
        throw new TypeError("Canonical tenantId and correlationId values are required.");
      }
      const bundle = await loadBundle({ tenantId,correlationId }, options);
      if (bundle?.tenantId !== tenantId || bundle?.correlationId !== correlationId
          || !Array.isArray(bundle.records) || !Array.isArray(bundle.evidenceAnchors) || bundle.records.length === 0) {
        fail("VERIFICATION_SOURCE_INVALID");
      }
      const verifiedEvents = [];
      for (const record of bundle.records) {
        const expected = validateDurableRecord(record, tenantId, correlationId);
        let ledgerValue;
        try {
          ledgerValue = await readCommitment({ tenantId,recordType: expected.ledgerValue.recordType,
            eventKeyHashSha256: expected.ledgerValue.eventKeyHashSha256 }, options);
        } catch (error) {
          fail("LEDGER_COMMITMENT_UNAVAILABLE", error);
        }
        if (!isDeepStrictEqual(ledgerValue, expected.ledgerValue)
            || !verifyAuditCommitment({ channelName: record.channelName,event: record.event,
              ledgerKey: expected.ledgerKey,ledgerValue })) fail("LEDGER_COMMITMENT_MISMATCH");
        verifiedEvents.push(Object.freeze({ eventId: record.eventId,eventType: record.event.eventType,
          recordType: expected.ledgerValue.recordType,transactionId: record.transactionId,blockNumber: record.blockNumber }));
      }
      const links = verifyLinks(bundle.records, bundle.evidenceAnchors);
      return Object.freeze({ verified: true,tenantId,correlationId,eventCount: verifiedEvents.length,
        commitmentCount: verifiedEvents.length,links,events: Object.freeze(verifiedEvents) });
    },
  });
}
