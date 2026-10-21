import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {
  AUDIT_EVENT_SELECTIONS,
  AUDIT_LEDGER_VALUE_FIELDS,
  buildAuditCommitment,
  canonicalizeAuditJson,
  verifyAuditCommitment,
} from "../src/audit-commitments.mjs";

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  transition: "trn_018f1234-5678-7abc-8def-0123456789ab",
  evidence: "evd_018f1234-5678-7abc-8def-0123456789ab",
  correlation: "cor_018f1234-5678-7abc-8def-0123456789ab",
};
const hash = "ab".repeat(32);

function trustEvent(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    eventId: "evt_018f1234-5678-7abc-8def-0123456789ab",
    eventType: "trust.updated.v1",
    tenantId: ids.tenant,
    subjectId: ids.subject,
    aggregateId: ids.transition,
    correlationId: ids.correlation,
    causationId: "evt_018f1234-5678-7abc-8def-0123456789ac",
    idempotencyKey: "trust:transition:demo-1",
    occurredAt: "2026-10-21T08:00:00.000Z",
    recordedAt: "2026-10-21T08:00:00.100Z",
    producer: { service: "trust-engine", instanceId: "trust-1" },
    payload: {
      transitionId: ids.transition,
      previousScore: 86,
      newScore: 62,
      previousBand: "trusted",
      newBand: "restricted",
      modelVersion: "1.0.0",
      configurationVersion: 3,
      evidenceIds: [ids.evidence],
      explanationHashSha256: hash,
    },
    ...overrides,
  };
}

function reverseObjectKeys(value) {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).reverse().map(([key, entry]) => [key, reverseObjectKeys(entry)]),
    );
  }
  return value;
}

test("selection includes the scoped event classes and excludes evidence telemetry", () => {
  assert.equal(Object.keys(AUDIT_EVENT_SELECTIONS).length, 14);
  assert.equal(AUDIT_EVENT_SELECTIONS["certificate.revoked.v1"], "certificate-lifecycle");
  assert.equal(AUDIT_EVENT_SELECTIONS["trust.updated.v1"], "trust-transition");
  assert.equal(AUDIT_EVENT_SELECTIONS["policy.activated.v1"], "policy-change");
  assert.equal(AUDIT_EVENT_SELECTIONS["access.decided.v1"], "access-decision");
  assert.equal(AUDIT_EVENT_SELECTIONS["security-action.failed.v1"], "security-action");
  assert.equal(AUDIT_EVENT_SELECTIONS["evidence.accepted.v1"], undefined);
  assert.equal(AUDIT_EVENT_SELECTIONS["evidence.rejected.v1"], undefined);
});

test("canonical audit JSON is stable across object insertion order", () => {
  assert.equal(
    canonicalizeAuditJson({ z: 1, a: { y: 2, x: [3, true] } }),
    '{"a":{"x":[3,true],"y":2},"z":1}',
  );
  assert.throws(() => canonicalizeAuditJson({ value: Number.NaN }), /Unsupported canonical JSON/);
  assert.throws(() => canonicalizeAuditJson({ value: undefined }), /Unsupported canonical JSON/);
});

test("a selected event produces a deterministic minimal public commitment", () => {
  const event = trustEvent();
  const first = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event });
  const reordered = reverseObjectKeys(event);
  const second = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event: reordered });

  assert.deepEqual(Object.keys(first.ledgerValue).sort(), [...AUDIT_LEDGER_VALUE_FIELDS]);
  assert.equal(first.ledgerValue.recordType, "trust-transition");
  assert.match(first.ledgerKey, /^audit~trust-transition~[0-9a-f]{64}$/);
  assert.equal(first.ledgerKey, second.ledgerKey);
  assert.equal(first.ledgerValue.commitmentHashSha256, second.ledgerValue.commitmentHashSha256);
  assert.equal(JSON.stringify(first.ledgerValue).includes(ids.tenant), false);
  assert.equal(JSON.stringify(first.ledgerValue).includes(ids.subject), false);
  assert.equal(JSON.stringify(first.ledgerValue).includes(event.eventId), false);
});

test("payload changes alter the commitment without changing the opaque event key", () => {
  const original = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event: trustEvent() });
  const changed = buildAuditCommitment({
    channelName: "tt-audit-alpha-v1",
    event: trustEvent({ payload: { ...trustEvent().payload, newScore: 61 } }),
  });
  assert.equal(original.ledgerValue.eventKeyHashSha256, changed.ledgerValue.eventKeyHashSha256);
  assert.notEqual(original.ledgerValue.commitmentHashSha256, changed.ledgerValue.commitmentHashSha256);
});

test("verification detects preimage, key and public-value tampering", () => {
  const event = trustEvent();
  const commitment = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event });
  assert.equal(verifyAuditCommitment({ channelName: "tt-audit-alpha-v1", event, ...commitment }), true);
  assert.equal(verifyAuditCommitment({
    channelName: "tt-audit-alpha-v1",
    event: trustEvent({ payload: { ...event.payload, newScore: 61 } }),
    ...commitment,
  }), false);
  assert.equal(verifyAuditCommitment({
    channelName: "tt-audit-alpha-v1",
    event,
    ...commitment,
    ledgerKey: `${commitment.ledgerKey}0`,
  }), false);
  assert.equal(verifyAuditCommitment({
    channelName: "tt-audit-alpha-v1",
    event,
    ledgerKey: commitment.ledgerKey,
    ledgerValue: { ...commitment.ledgerValue, tenantId: ids.tenant },
  }), false);
});

test("unselected and schema-invalid events cannot become commitments", () => {
  const event = trustEvent();
  assert.throws(
    () => buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event: { ...event, eventType: "evidence.accepted.v1" } }),
    /not selected/,
  );
  assert.throws(
    () => buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event: { ...event, rawEvidence: { ipAddress: "192.0.2.1" } } }),
    /failed its canonical schema/,
  );
  assert.throws(
    () => buildAuditCommitment({ channelName: "tenant-alpha", event }),
    /versioned tenant audit channel/,
  );
});

test("the public ledger schema accepts only the approved minimal fields", () => {
  const schema = JSON.parse(readFileSync(new URL("../schemas/audit/audit-ledger-commitment.schema.json", import.meta.url), "utf8"));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const { ledgerValue } = buildAuditCommitment({ channelName: "tt-audit-alpha-v1", event: trustEvent() });
  assert.equal(validate(ledgerValue), true);
  assert.equal(validate({ ...ledgerValue, subjectId: ids.subject }), false);
});
