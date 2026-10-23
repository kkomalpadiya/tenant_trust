import { isDeepStrictEqual } from "node:util";
import {
  buildAuditCommitment,
  verifyAuditCommitment,
} from "@tenant-trust/contracts/audit-commitments";

const TENANT_ID = /^tnt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SUBJECT_ID = /^sub_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CERTIFICATE_ID = /^crt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_ID = /^evt_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACTION_ID = /^act_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DECISION_ID = /^dec_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CORRELATION_ID = /^cor_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const AUTHORIZATION_ID = /^rca_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRANSITION_ID = /^trn_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CHANNEL = /^tt-audit-[a-z0-9-]+-v[1-9][0-9]*$/u;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const EXTERNAL_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/u;
const ACTION_TYPES = new Set([
  "restrict-access",
  "suspend-subject",
  "block-renewal",
  "revoke-certificate",
  "restore-access",
  "issue-replacement-certificate",
]);
const AUTHORITY_CLASSES = new Set(["policy-quarantine", "severity-rule", "recovery-authorization"]);
const EVENT_STATUS = Object.freeze({
  "security-action.requested.v1": "requested",
  "security-action.succeeded.v1": "succeeded",
  "security-action.failed.v1": "failed",
});
const SOURCE_FIELDS = [
  "actionId", "actionType", "attemptNumber", "authorityClass", "authorizedBySubjectId",
  "causationEventId", "causeResolutionReference", "certificateEventId", "correlationId",
  "decisionId", "eventId", "eventType", "externalReference", "failureCode", "occurredAt",
  "reasonCode", "recordedAt", "recoveryAuthorizationId", "recoveryTrustTransitionId",
  "status", "targetCertificateId", "targetSubjectId", "tenantId",
];
const RECORD_FIELDS = [
  "blockNumber", "canonicalPreimageJson", "channelName", "deliveryStatus", "event", "eventId",
  "ledgerKey", "ledgerValue", "tenantId", "transactionId", "validationCode",
];
const SQL = Object.freeze({
  next: "SELECT * FROM audit.get_pending_security_action_audit_event()",
  record: "SELECT * FROM audit.record_security_action_audit_commitment($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9::jsonb,$10)",
  expectations: "SELECT * FROM audit.list_security_action_audit_expectations($1,$2)",
  records: "SELECT * FROM audit.list_security_action_audit_records($1,$2)",
});

export const SECURITY_ACTION_AUDIT_POLICY = Object.freeze({
  producer: Object.freeze({ service: "security-action-audit", instanceId: "projection-v1" }),
  recordType: "security-action",
  delivery: "durable-projection-to-fabric-outbox",
  recoveryCausation: "recovered-trust-transition",
  terminalCausation: "requested-action-event",
});

export class SecurityActionAuditError extends Error {
  constructor(reasonCode, options) {
    super("Security-action audit anchoring failed.", options);
    this.name = "SecurityActionAuditError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode, cause) {
  throw new SecurityActionAuditError(reasonCode, cause === undefined ? undefined : { cause });
}

function exact(value, fields) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && isDeepStrictEqual(Object.keys(value).sort(), fields);
}

function iso(value) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) fail("ACTION_AUDIT_SOURCE_INVALID");
  return parsed.toISOString();
}

function nullable(value) {
  return value ?? null;
}

function sourceFromRow(row) {
  if (!row) return null;
  const value = {
    tenantId: row.tenant_id,
    eventId: row.event_id,
    actionId: row.action_id,
    eventType: row.event_type,
    status: row.event_status,
    attemptNumber: Number(row.attempt_number),
    decisionId: row.decision_id,
    correlationId: row.correlation_id,
    targetSubjectId: row.target_subject_id,
    targetCertificateId: row.target_certificate_id,
    actionType: row.action_type,
    authorityClass: row.authority_class,
    reasonCode: row.reason_code,
    recoveryAuthorizationId: nullable(row.recovery_authorization_id),
    recoveryTrustTransitionId: nullable(row.recovery_trust_transition_id),
    authorizedBySubjectId: nullable(row.recovery_authorized_by_subject_id),
    causeResolutionReference: nullable(row.cause_resolution_reference),
    externalReference: nullable(row.external_reference),
    failureCode: nullable(row.failure_code),
    occurredAt: iso(row.occurred_at),
    recordedAt: iso(row.recorded_at),
    causationEventId: nullable(row.causation_event_id),
    certificateEventId: nullable(row.certificate_event_id),
  };
  validateSource(value);
  return Object.freeze(value);
}

function validateSource(value) {
  if (!exact(value, SOURCE_FIELDS)
    || !TENANT_ID.test(value.tenantId ?? "")
    || !EVENT_ID.test(value.eventId ?? "")
    || !ACTION_ID.test(value.actionId ?? "")
    || EVENT_STATUS[value.eventType] !== value.status
    || !Number.isSafeInteger(value.attemptNumber)
    || value.attemptNumber < 0
    || (value.status === "requested" && value.attemptNumber !== 0)
    || (value.status !== "requested" && value.attemptNumber < 1)
    || !DECISION_ID.test(value.decisionId ?? "")
    || !CORRELATION_ID.test(value.correlationId ?? "")
    || !SUBJECT_ID.test(value.targetSubjectId ?? "")
    || !CERTIFICATE_ID.test(value.targetCertificateId ?? "")
    || !ACTION_TYPES.has(value.actionType)
    || !AUTHORITY_CLASSES.has(value.authorityClass)
    || !REASON_CODE.test(value.reasonCode ?? "")
    || (value.causationEventId !== null && !EVENT_ID.test(value.causationEventId ?? ""))
    || (value.certificateEventId !== null && !EVENT_ID.test(value.certificateEventId ?? ""))
    || (value.externalReference !== null && !EXTERNAL_REFERENCE.test(value.externalReference ?? ""))
    || (value.failureCode !== null && !REASON_CODE.test(value.failureCode ?? ""))) {
    fail("ACTION_AUDIT_SOURCE_INVALID");
  }
  const recovery = value.authorityClass === "recovery-authorization";
  if (recovery !== (AUTHORIZATION_ID.test(value.recoveryAuthorizationId ?? "")
      && TRANSITION_ID.test(value.recoveryTrustTransitionId ?? "")
      && SUBJECT_ID.test(value.authorizedBySubjectId ?? ""))
    || (!recovery && (value.recoveryAuthorizationId !== null
      || value.recoveryTrustTransitionId !== null
      || value.authorizedBySubjectId !== null
      || value.causeResolutionReference !== null))
    || (value.status === "failed") !== (value.failureCode !== null)) {
    fail("ACTION_AUDIT_SOURCE_INVALID");
  }
}

export function buildSecurityActionAuditEvent(source) {
  validateSource(source);
  if (source.causationEventId === null) fail("ACTION_AUDIT_CAUSATION_PENDING");
  if (source.status === "succeeded"
    && ["revoke-certificate", "issue-replacement-certificate"].includes(source.actionType)
    && source.certificateEventId === null) {
    fail("ACTION_AUDIT_CERTIFICATE_EVENT_PENDING");
  }
  const payload = {
    actionId: source.actionId,
    decisionId: source.decisionId,
    actionType: source.actionType,
    status: source.status,
    targetCertificateId: source.targetCertificateId,
    reasonCode: source.reasonCode,
    authorityClass: source.authorityClass,
    attemptNumber: source.attemptNumber,
    recoveryAuthorizationId: source.recoveryAuthorizationId,
    recoveryTrustTransitionId: source.recoveryTrustTransitionId,
    authorizedBySubjectId: source.authorizedBySubjectId,
    causeResolutionReference: source.causeResolutionReference,
    externalReference: source.externalReference,
    certificateEventId: source.certificateEventId,
  };
  if (source.failureCode !== null) payload.failureCode = source.failureCode;
  return Object.freeze({
    schemaVersion: "1.0.0",
    eventId: source.eventId,
    eventType: source.eventType,
    tenantId: source.tenantId,
    subjectId: source.targetSubjectId,
    aggregateId: source.actionId,
    correlationId: source.correlationId,
    causationId: source.causationEventId,
    idempotencyKey: `security-action-audit:${source.actionId}:${source.status}:${source.attemptNumber}`,
    occurredAt: source.occurredAt,
    recordedAt: source.recordedAt,
    producer: SECURITY_ACTION_AUDIT_POLICY.producer,
    payload: Object.freeze(payload),
  });
}

function one(result, reasonCode) {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) fail(reasonCode);
  return result.rows[0];
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
  if (!exact(value, RECORD_FIELDS)) fail("ACTION_AUDIT_VERIFICATION_SOURCE_INVALID");
  return Object.freeze(value);
}

export function createPostgresSecurityActionAuditRepository({ query, clock = () => new Date() } = {}) {
  if (typeof query !== "function" || typeof clock !== "function") {
    throw new TypeError("A projector-role PostgreSQL query function and clock are required.");
  }
  return Object.freeze({
    async loadNext(options = {}) {
      const result = await query(SQL.next, [], options);
      if (!result || !Array.isArray(result.rows) || result.rows.length > 1) {
        fail("ACTION_AUDIT_SOURCE_INVALID");
      }
      return sourceFromRow(result.rows[0]);
    },
    async record({ source, channelName, event, commitment }, options = {}) {
      validateSource(source);
      if (!CHANNEL.test(channelName ?? "") || event.eventId !== source.eventId) {
        fail("ACTION_AUDIT_COMMITMENT_INVALID");
      }
      const row = one(await query(SQL.record, [
        source.tenantId,
        source.eventId,
        channelName,
        JSON.stringify(event),
        commitment.canonicalPreimageJson,
        commitment.ledgerKey,
        commitment.ledgerValue.eventKeyHashSha256,
        commitment.ledgerValue.commitmentHashSha256,
        JSON.stringify(commitment.ledgerValue),
        iso(clock()),
      ], options), "ACTION_AUDIT_COMMITMENT_INVALID");
      if (row.event_id !== source.eventId || !["pending", "submitting", "submitted", "confirming", "committed", "failed"].includes(row.status)) {
        fail("ACTION_AUDIT_COMMITMENT_INVALID");
      }
      return Object.freeze({ eventId: row.event_id, status: row.status });
    },
  });
}

export function createSecurityActionAuditProjector({ repository, channelForTenant } = {}) {
  if (!repository || typeof repository.loadNext !== "function" || typeof repository.record !== "function"
    || typeof channelForTenant !== "function") {
    throw new TypeError("A security-action audit repository and tenant channel resolver are required.");
  }
  return Object.freeze({
    async runOnce(options = {}) {
      const source = await repository.loadNext(options);
      if (!source) return Object.freeze({ status: "idle" });
      const channelName = await channelForTenant(source.tenantId);
      if (!CHANNEL.test(channelName ?? "")) fail("ACTION_AUDIT_CHANNEL_INVALID");
      const event = buildSecurityActionAuditEvent(source);
      const commitment = buildAuditCommitment({ channelName, event });
      const stored = await repository.record({ source, channelName, event, commitment }, options);
      return Object.freeze({
        status: stored.status,
        tenantId: source.tenantId,
        actionId: source.actionId,
        eventId: source.eventId,
        eventType: source.eventType,
        ledgerKey: commitment.ledgerKey,
      });
    },
  });
}

export function createPostgresSecurityActionAuditVerificationRepository({ query } = {}) {
  if (typeof query !== "function") throw new TypeError("A verifier-role PostgreSQL query function is required.");
  return Object.freeze({
    async loadBundle({ tenantId, correlationId }, options = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !CORRELATION_ID.test(correlationId ?? "")) {
        throw new TypeError("Canonical tenantId and correlationId values are required.");
      }
      const [expectations, records] = await Promise.all([
        query(SQL.expectations, [tenantId, correlationId], options),
        query(SQL.records, [tenantId, correlationId], options),
      ]);
      if (!Array.isArray(expectations?.rows) || !Array.isArray(records?.rows)) {
        fail("ACTION_AUDIT_VERIFICATION_SOURCE_INVALID");
      }
      return Object.freeze({
        tenantId,
        correlationId,
        expectations: Object.freeze(expectations.rows.map(sourceFromRow)),
        records: Object.freeze(records.rows.map(recordFromRow)),
      });
    },
  });
}

function validateCommittedRecord(record, tenantId) {
  if (!exact(record, RECORD_FIELDS) || record.tenantId !== tenantId
    || record.eventId !== record.event?.eventId || record.event?.tenantId !== tenantId
    || !CHANNEL.test(record.channelName ?? "") || record.deliveryStatus !== "committed"
    || !SHA256.test(record.transactionId ?? "") || record.validationCode !== 0
    || !Number.isSafeInteger(record.blockNumber) || record.blockNumber < 0) {
    fail(record.deliveryStatus === "committed"
      ? "ACTION_AUDIT_VERIFICATION_SOURCE_INVALID"
      : "ACTION_AUDIT_DELIVERY_NOT_COMMITTED");
  }
  const expected = buildAuditCommitment({ channelName: record.channelName, event: record.event });
  if (record.canonicalPreimageJson !== expected.canonicalPreimageJson
    || record.ledgerKey !== expected.ledgerKey
    || !isDeepStrictEqual(record.ledgerValue, expected.ledgerValue)
    || !verifyAuditCommitment({ channelName: record.channelName, event: record.event,
      ledgerKey: record.ledgerKey, ledgerValue: record.ledgerValue })) {
    fail("ACTION_AUDIT_OFFCHAIN_MISMATCH");
  }
  return expected;
}

function recordById(records, eventId, reasonCode) {
  const matches = records.filter((record) => record.eventId === eventId);
  if (matches.length !== 1) fail(reasonCode);
  return matches[0];
}

function verifyCausalLink(source, event, records) {
  const cause = recordById(records, source.causationEventId, "ACTION_AUDIT_CAUSE_MISSING").event;
  if (source.status === "requested" && source.authorityClass === "recovery-authorization") {
    if (cause.eventType !== "trust.updated.v1"
      || cause.subjectId !== source.targetSubjectId
      || cause.payload?.transitionId !== source.recoveryTrustTransitionId) {
      fail("ACTION_AUDIT_RECOVERY_LINK_INVALID");
    }
  } else if (source.status === "requested") {
    if (cause.eventType !== "access.decided.v1"
      || cause.subjectId !== source.targetSubjectId
      || cause.payload?.decisionId !== source.decisionId
      || cause.payload?.certificateId !== source.targetCertificateId) {
      fail("ACTION_AUDIT_DECISION_LINK_INVALID");
    }
  } else if (cause.eventType !== "security-action.requested.v1"
    || cause.payload?.actionId !== source.actionId) {
    fail("ACTION_AUDIT_TERMINAL_LINK_INVALID");
  }
  if (event.causationId !== cause.eventId) fail("ACTION_AUDIT_EVENT_MISMATCH");
}

function verifyCertificateLink(source, records) {
  if (source.certificateEventId === null) return 0;
  const certificate = recordById(records, source.certificateEventId, "ACTION_AUDIT_CERTIFICATE_EVENT_MISSING").event;
  if (source.actionType === "revoke-certificate") {
    if (certificate.eventType !== "certificate.revoked.v1"
      || certificate.subjectId !== source.targetSubjectId
      || certificate.payload?.certificateId !== source.targetCertificateId
      || certificate.payload?.state !== "revoked") {
      fail("ACTION_AUDIT_CERTIFICATE_LINK_INVALID");
    }
  } else if (source.actionType === "issue-replacement-certificate") {
    if (certificate.eventType !== "certificate.issued.v1"
      || certificate.subjectId !== source.targetSubjectId
      || certificate.payload?.certificateId !== source.externalReference
      || certificate.payload?.state !== "active") {
      fail("ACTION_AUDIT_CERTIFICATE_LINK_INVALID");
    }
  } else {
    fail("ACTION_AUDIT_CERTIFICATE_LINK_INVALID");
  }
  return 1;
}

export function createSecurityActionAuditVerifier({ loadBundle, readCommitment } = {}) {
  if (typeof loadBundle !== "function" || typeof readCommitment !== "function") {
    throw new TypeError("Security-action audit source and Fabric commitment readers are required.");
  }
  return Object.freeze({
    async verify({ tenantId, correlationId }, options = {}) {
      if (!TENANT_ID.test(tenantId ?? "") || !CORRELATION_ID.test(correlationId ?? "")) {
        throw new TypeError("Canonical tenantId and correlationId values are required.");
      }
      const bundle = await loadBundle({ tenantId, correlationId }, options);
      if (bundle?.tenantId !== tenantId || bundle?.correlationId !== correlationId
        || !Array.isArray(bundle.expectations) || !Array.isArray(bundle.records)
        || bundle.expectations.length === 0) {
        fail("ACTION_AUDIT_VERIFICATION_SOURCE_INVALID");
      }
      const records = bundle.records;
      const validated = new Map();
      for (const record of records) validated.set(record.eventId, validateCommittedRecord(record, tenantId));
      const actionRecordIds = new Set(records
        .filter(({ event }) => event.eventType?.startsWith("security-action."))
        .map(({ eventId }) => eventId));
      if (actionRecordIds.size !== bundle.expectations.length
        || bundle.expectations.some(({ eventId }) => !actionRecordIds.has(eventId))) {
        fail("ACTION_AUDIT_EVENT_MISSING");
      }
      let certificateLinks = 0;
      let recoveryLinks = 0;
      for (const source of bundle.expectations) {
        const record = recordById(records, source.eventId, "ACTION_AUDIT_EVENT_MISSING");
        const expectedEvent = buildSecurityActionAuditEvent(source);
        if (!isDeepStrictEqual(record.event, expectedEvent)) fail("ACTION_AUDIT_EVENT_MISMATCH");
        verifyCausalLink(source, record.event, records);
        certificateLinks += verifyCertificateLink(source, records);
        if (source.authorityClass === "recovery-authorization") recoveryLinks += 1;
        let ledgerValue;
        try {
          const expected = validated.get(record.eventId);
          ledgerValue = await readCommitment({ tenantId, recordType: expected.ledgerValue.recordType,
            eventKeyHashSha256: expected.ledgerValue.eventKeyHashSha256 }, options);
        } catch (error) {
          fail("ACTION_AUDIT_LEDGER_UNAVAILABLE", error);
        }
        if (!isDeepStrictEqual(ledgerValue, record.ledgerValue)) fail("ACTION_AUDIT_LEDGER_MISMATCH");
      }
      return Object.freeze({
        verified: true,
        tenantId,
        correlationId,
        actionEventCount: bundle.expectations.length,
        recoveryLinks,
        certificateLinks,
      });
    },
  });
}
