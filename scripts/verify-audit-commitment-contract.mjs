import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  AUDIT_EVENT_SELECTIONS,
  AUDIT_LEDGER_VALUE_FIELDS,
  AUDIT_RECORD_TYPES,
} from "../packages/contracts/src/audit-commitments.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const readJson = (relativePath) => JSON.parse(readFileSync(`${root}/${relativePath}`, "utf8"));
const registry = readJson("packages/contracts/schemas/event-registry.json");
const topology = readJson("config/fabric-topology.json");

const expectedSelections = {
  "access.decided.v1": "access-decision",
  "certificate.expired.v1": "certificate-lifecycle",
  "certificate.issued.v1": "certificate-lifecycle",
  "certificate.renewed.v1": "certificate-lifecycle",
  "certificate.requested.v1": "certificate-lifecycle",
  "certificate.revoked.v1": "certificate-lifecycle",
  "certificate.superseded.v1": "certificate-lifecycle",
  "policy.activated.v1": "policy-change",
  "policy.published.v1": "policy-change",
  "policy.rolled-back.v1": "policy-change",
  "security-action.failed.v1": "security-action",
  "security-action.requested.v1": "security-action",
  "security-action.succeeded.v1": "security-action",
  "trust.updated.v1": "trust-transition",
};

assert.deepEqual(AUDIT_EVENT_SELECTIONS, expectedSelections);
for (const eventType of Object.keys(AUDIT_EVENT_SELECTIONS)) {
  assert(registry.events[eventType], `selected event is absent from registry: ${eventType}`);
}
for (const excluded of [
  "evidence.accepted.v1",
  "evidence.rejected.v1",
  "tenant.created.v1",
  "subject.provisioned.v1",
]) {
  assert.equal(AUDIT_EVENT_SELECTIONS[excluded], undefined, `${excluded} must stay outside the commitment selection`);
}

assert.deepEqual(AUDIT_RECORD_TYPES, [
  "access-decision",
  "certificate-lifecycle",
  "policy-change",
  "security-action",
  "trust-transition",
]);
assert.deepEqual(AUDIT_LEDGER_VALUE_FIELDS, [
  "canonicalizationProfile",
  "commitmentHashSha256",
  "digestAlgorithm",
  "eventKeyHashSha256",
  "recordType",
  "schemaVersion",
]);

assert.equal(topology.dataBoundary.rawEvidenceOnChain, false);
assert.equal(topology.dataBoundary.detailedApplicationStateOnChain, false);
assert.equal(topology.dataBoundary.plainTenantIdOnChain, false);
assert.equal(topology.dataBoundary.plainSubjectOrResourceIdOnChain, false);
assert.equal(topology.dataBoundary.commitmentPreimagesOffChain, true);
for (const channel of topology.channels) {
  assert.equal(channel.publicState, "commitments-only");
  assert.deepEqual(channel.privateDataCollections, []);
}

console.log("Audit commitment contract verified: 14 selected event types, 5 public record classes, 6 approved ledger value fields.");
