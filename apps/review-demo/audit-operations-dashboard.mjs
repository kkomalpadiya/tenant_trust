import { AUDIT_OUTBOX_POLICY } from "../../services/audit/src/index.mjs";
import { SECURITY_ACTION_OPERATIONS_POLICY } from "../../services/orchestrator/src/index.mjs";
import { getReviewPersona, resolveReviewContext, reviewIds } from "./demo-domain.mjs";

const ledgerDefinitions = Object.freeze([
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    recordReference: "AUD-ALPHA-1042",
    recordType: "trust-transition",
    eventType: "trust.updated.v1",
    deliveryStatus: "committed",
    occurredAt: "2026-10-27T08:48:00.000Z",
    attemptCount: 1,
    blockNumber: 184,
    transactionReference: "tx…8ca4",
    failureCode: null,
    nextAttemptAt: null,
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    recordReference: "AUD-ALPHA-1043",
    recordType: "access-decision",
    eventType: "access.decided.v1",
    deliveryStatus: "pending",
    occurredAt: "2026-10-27T09:02:00.000Z",
    attemptCount: 0,
    blockNumber: null,
    transactionReference: null,
    failureCode: null,
    nextAttemptAt: "2026-10-27T09:02:05.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    recordReference: "AUD-ALPHA-1044",
    recordType: "security-action",
    eventType: "security-action.failed.v1",
    deliveryStatus: "failed",
    occurredAt: "2026-10-27T09:07:00.000Z",
    attemptCount: 2,
    blockNumber: null,
    transactionReference: null,
    failureCode: "FABRIC_GATEWAY_UNAVAILABLE",
    nextAttemptAt: "2026-10-27T09:07:10.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alphaAdmin,
    recordReference: "AUD-ALPHA-1039",
    recordType: "certificate-event",
    eventType: "certificate.issued.v1",
    deliveryStatus: "committed",
    occurredAt: "2026-10-27T08:22:00.000Z",
    attemptCount: 1,
    blockNumber: 181,
    transactionReference: "tx…92bd",
    failureCode: null,
    nextAttemptAt: null,
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.bob,
    recordReference: "AUD-BETA-0831",
    recordType: "trust-transition",
    eventType: "trust.updated.v1",
    deliveryStatus: "committed",
    occurredAt: "2026-10-27T08:36:00.000Z",
    attemptCount: 1,
    blockNumber: 97,
    transactionReference: "tx…21ef",
    failureCode: null,
    nextAttemptAt: null,
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.bob,
    recordReference: "AUD-BETA-0832",
    recordType: "security-action",
    eventType: "security-action.requested.v1",
    deliveryStatus: "failed",
    occurredAt: "2026-10-27T08:38:00.000Z",
    attemptCount: 3,
    blockNumber: null,
    transactionReference: null,
    failureCode: "FABRIC_COMMIT_INVALID",
    nextAttemptAt: "2026-10-27T08:38:20.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.betaAdmin,
    recordReference: "AUD-BETA-0833",
    recordType: "access-decision",
    eventType: "access.decided.v1",
    deliveryStatus: "pending",
    occurredAt: "2026-10-27T09:11:00.000Z",
    attemptCount: 0,
    blockNumber: null,
    transactionReference: null,
    failureCode: null,
    nextAttemptAt: "2026-10-27T09:11:05.000Z",
  }),
]);

const causalDefinitions = Object.freeze([
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    correlationReference: "COR-ALPHA-0041",
    result: "verified",
    reasonCode: "CAUSAL_CHAIN_VERIFIED",
    eventCount: 5,
    verifiedLinks: Object.freeze(["evidence", "trust", "policy", "decision", "certificate action"]),
    checkedAt: "2026-10-27T09:00:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    correlationReference: "COR-ALPHA-0042",
    result: "waiting",
    reasonCode: "AUDIT_DELIVERY_NOT_COMMITTED",
    eventCount: 2,
    verifiedLinks: Object.freeze(["evidence", "trust"]),
    checkedAt: "2026-10-27T09:04:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alphaAdmin,
    correlationReference: "COR-ALPHA-0038",
    result: "failed",
    reasonCode: "CAUSATION_LINK_MISSING",
    eventCount: 4,
    verifiedLinks: Object.freeze(["evidence", "trust", "policy"]),
    checkedAt: "2026-10-27T08:29:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.bob,
    correlationReference: "COR-BETA-0027",
    result: "failed",
    reasonCode: "LEDGER_COMMITMENT_MISMATCH",
    eventCount: 5,
    verifiedLinks: Object.freeze(["evidence", "trust", "policy", "decision"]),
    checkedAt: "2026-10-27T08:42:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.betaAdmin,
    correlationReference: "COR-BETA-0028",
    result: "verified",
    reasonCode: "CAUSAL_CHAIN_VERIFIED",
    eventCount: 5,
    verifiedLinks: Object.freeze(["evidence", "trust", "policy", "decision", "certificate action"]),
    checkedAt: "2026-10-27T08:55:00.000Z",
  }),
]);

const actionDefinitions = Object.freeze([
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    actionReference: "ACT-ALPHA-071",
    actionType: "restrict-access",
    authority: "policy-quarantine",
    status: "succeeded",
    severity: "info",
    issueCode: "ACTION_HEALTHY",
    attemptCount: 1,
    retryable: false,
    auditDeliveryStatus: "committed",
    nextAttemptAt: null,
    observedAt: "2026-10-27T08:51:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    actionReference: "ACT-ALPHA-072",
    actionType: "suspend-subject",
    authority: "policy-quarantine",
    status: "failed",
    severity: "critical",
    issueCode: "ACTION_EXECUTION_FAILED",
    attemptCount: 2,
    retryable: true,
    auditDeliveryStatus: "failed",
    nextAttemptAt: "2026-10-27T09:08:00.000Z",
    observedAt: "2026-10-27T09:07:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alphaAdmin,
    actionReference: "ACT-ALPHA-068",
    actionType: "restore-access",
    authority: "recovery-authorization",
    status: "pending",
    severity: "warning",
    issueCode: "ACTION_RETRY_SCHEDULED",
    attemptCount: 1,
    retryable: true,
    auditDeliveryStatus: "pending",
    nextAttemptAt: "2026-10-27T09:14:00.000Z",
    observedAt: "2026-10-27T09:09:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.bob,
    actionReference: "ACT-BETA-052",
    actionType: "revoke-certificate",
    authority: "severity-rule",
    status: "failed",
    severity: "critical",
    issueCode: "AUDIT_COMMITMENT_FAILED",
    attemptCount: 3,
    retryable: true,
    auditDeliveryStatus: "failed",
    nextAttemptAt: "2026-10-27T08:39:00.000Z",
    observedAt: "2026-10-27T08:38:00.000Z",
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.betaAdmin,
    actionReference: "ACT-BETA-053",
    actionType: "restrict-access",
    authority: "policy-quarantine",
    status: "pending",
    severity: "warning",
    issueCode: "ACTION_PENDING",
    attemptCount: 0,
    retryable: true,
    auditDeliveryStatus: "pending",
    nextAttemptAt: "2026-10-27T09:12:00.000Z",
    observedAt: "2026-10-27T09:11:00.000Z",
  }),
]);

function visibleFor(context, entry) {
  return entry.tenantId === context.tenantId
    && (entry.subjectId === context.subjectId || context.roles.includes("tenant-admin"));
}

function countBy(items, property, values) {
  return Object.freeze(Object.fromEntries(values.map((value) => [
    value,
    items.filter((item) => item[property] === value).length,
  ])));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export function createAuditOperationsDashboard() {
  function getState(personaKey = "alpha-member") {
    const persona = getReviewPersona(personaKey);
    const context = resolveReviewContext(personaKey);
    const ledgerDeliveries = ledgerDefinitions.filter((entry) => visibleFor(context, entry));
    const causalChecks = causalDefinitions.filter((entry) => visibleFor(context, entry));
    const securityActions = actionDefinitions.filter((entry) => visibleFor(context, entry));
    const ledgerCounts = countBy(ledgerDeliveries, "deliveryStatus", ["committed", "pending", "failed"]);
    const causalCounts = countBy(causalChecks, "result", ["verified", "waiting", "failed"]);
    const actionCounts = countBy(securityActions, "severity", ["critical", "warning", "info"]);

    return deepFreeze({
      auditOperations: {
        scope: {
          tenantId: context.tenantId,
          tenantName: persona.tenant.name,
          mode: context.roles.includes("tenant-admin") ? "tenant" : "self",
          subjectId: context.roles.includes("tenant-admin") ? null : context.subjectId,
        },
        summary: {
          ledger: ledgerCounts,
          causal: causalCounts,
          actions: actionCounts,
          health: actionCounts.critical > 0 ? "critical" : actionCounts.warning > 0 ? "attention" : "healthy",
        },
        ledgerDeliveries,
        causalChecks,
        securityActions,
        policies: {
          delivery: AUDIT_OUTBOX_POLICY.delivery,
          maximumRetryDelaySeconds: AUDIT_OUTBOX_POLICY.maximumRetryDelaySeconds,
          stuckPendingSeconds: SECURITY_ACTION_OPERATIONS_POLICY.stuckPendingSeconds,
          auditDeliveryRequiredForHealthy: SECURITY_ACTION_OPERATIONS_POLICY.auditDeliveryRequiredForHealthy,
        },
        privacy: {
          evidenceContentFields: 0,
          secretFields: 0,
          identifiers: "review references only",
        },
      },
    });
  }

  return Object.freeze({ getState });
}
