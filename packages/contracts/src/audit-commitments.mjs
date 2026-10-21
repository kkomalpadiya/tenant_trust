import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

export const AUDIT_COMMITMENT_SCHEMA_VERSION = "1.0.0";
export const AUDIT_CANONICALIZATION_PROFILE = "tenant-trust-audit-commitment-json-v1";
export const AUDIT_DIGEST_ALGORITHM = "sha256";

const COMMITMENT_DOMAIN = "tenant-trust:audit-commitment:v1";
const EVENT_KEY_DOMAIN = "tenant-trust:audit-event-key:v1";
const CHANNEL_PATTERN = /^tt-audit-[a-z0-9-]+-v[1-9][0-9]*$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export const AUDIT_EVENT_SELECTIONS = Object.freeze({
  "certificate.requested.v1": "certificate-lifecycle",
  "certificate.issued.v1": "certificate-lifecycle",
  "certificate.renewed.v1": "certificate-lifecycle",
  "certificate.superseded.v1": "certificate-lifecycle",
  "certificate.revoked.v1": "certificate-lifecycle",
  "certificate.expired.v1": "certificate-lifecycle",
  "trust.updated.v1": "trust-transition",
  "policy.published.v1": "policy-change",
  "policy.activated.v1": "policy-change",
  "policy.rolled-back.v1": "policy-change",
  "access.decided.v1": "access-decision",
  "security-action.requested.v1": "security-action",
  "security-action.succeeded.v1": "security-action",
  "security-action.failed.v1": "security-action",
});

export const AUDIT_RECORD_TYPES = Object.freeze(
  [...new Set(Object.values(AUDIT_EVENT_SELECTIONS))].sort(),
);

export const AUDIT_LEDGER_VALUE_FIELDS = Object.freeze([
  "canonicalizationProfile",
  "commitmentHashSha256",
  "digestAlgorithm",
  "eventKeyHashSha256",
  "recordType",
  "schemaVersion",
]);

const schemaRoot = new URL("../schemas/", import.meta.url);
const registry = JSON.parse(readFileSync(new URL("event-registry.json", schemaRoot), "utf8"));
const commonSchema = JSON.parse(readFileSync(new URL("common.schema.json", schemaRoot), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(commonSchema);

const selectedSchemaFiles = [...new Set(
  Object.keys(AUDIT_EVENT_SELECTIONS).map((eventType) => {
    const schemaFile = registry.events[eventType];
    if (!schemaFile) throw new Error(`Selected audit event is missing from the registry: ${eventType}`);
    return schemaFile;
  }),
)];

const validatorBySchemaFile = new Map(
  selectedSchemaFiles.map((schemaFile) => {
    const schema = JSON.parse(readFileSync(new URL(schemaFile, schemaRoot), "utf8"));
    return [schemaFile, ajv.compile(schema)];
  }),
);

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalValue(value, path = "$") {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`Sparse arrays are not canonical JSON at ${path}[${index}]`);
    }
    return `[${value.map((entry, index) => canonicalValue(entry, `${path}[${index}]`)).join(",")}]`;
  }
  if (isPlainObject(value)) {
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError(`Symbol keys are not canonical JSON at ${path}`);
    }
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key], `${path}.${key}`)}`).join(",")}}`;
  }
  throw new TypeError(`Unsupported canonical JSON value at ${path}`);
}

export function canonicalizeAuditJson(value) {
  return canonicalValue(value);
}

function hashCanonical(domain, value) {
  return createHash("sha256")
    .update(`${domain}\n${canonicalizeAuditJson(value)}`, "utf8")
    .digest("hex");
}

function assertChannelName(channelName) {
  if (typeof channelName !== "string" || !CHANNEL_PATTERN.test(channelName)) {
    throw new TypeError("channelName must be a versioned tenant audit channel name");
  }
}

export function assertSelectedAuditEvent(event) {
  if (!isPlainObject(event)) throw new TypeError("event must be a plain JSON object");
  const recordType = AUDIT_EVENT_SELECTIONS[event.eventType];
  if (!recordType) throw new TypeError(`Event type is not selected for audit commitment: ${event.eventType ?? "<missing>"}`);

  const schemaFile = registry.events[event.eventType];
  const validate = validatorBySchemaFile.get(schemaFile);
  assert(validate, `No validator compiled for ${schemaFile}`);
  if (!validate(event)) {
    throw new TypeError(`Selected audit event failed its canonical schema: ${ajv.errorsText(validate.errors)}`);
  }
  return recordType;
}

export function assertAuditLedgerValue(value) {
  if (!isPlainObject(value)) throw new TypeError("ledgerValue must be a plain JSON object");
  const keys = Object.keys(value).sort();
  if (keys.length !== AUDIT_LEDGER_VALUE_FIELDS.length
      || !keys.every((key, index) => key === AUDIT_LEDGER_VALUE_FIELDS[index])) {
    throw new TypeError("ledgerValue contains missing or unapproved public fields");
  }
  if (value.schemaVersion !== AUDIT_COMMITMENT_SCHEMA_VERSION) throw new TypeError("Unsupported ledger commitment schemaVersion");
  if (!AUDIT_RECORD_TYPES.includes(value.recordType)) throw new TypeError("Unsupported ledger recordType");
  if (value.canonicalizationProfile !== AUDIT_CANONICALIZATION_PROFILE) throw new TypeError("Unsupported canonicalizationProfile");
  if (value.digestAlgorithm !== AUDIT_DIGEST_ALGORITHM) throw new TypeError("Unsupported digestAlgorithm");
  if (!SHA256_PATTERN.test(value.eventKeyHashSha256)) throw new TypeError("Invalid eventKeyHashSha256");
  if (!SHA256_PATTERN.test(value.commitmentHashSha256)) throw new TypeError("Invalid commitmentHashSha256");
}

export function buildAuditCommitment({ channelName, event }) {
  assertChannelName(channelName);
  const recordType = assertSelectedAuditEvent(event);

  const preimage = {
    canonicalizationProfile: AUDIT_CANONICALIZATION_PROFILE,
    channelName,
    event,
    schemaVersion: AUDIT_COMMITMENT_SCHEMA_VERSION,
  };
  const canonicalPreimageJson = canonicalizeAuditJson(preimage);
  const eventKeyHashSha256 = hashCanonical(EVENT_KEY_DOMAIN, {
    channelName,
    eventId: event.eventId,
    tenantId: event.tenantId,
  });
  const commitmentHashSha256 = createHash("sha256")
    .update(`${COMMITMENT_DOMAIN}\n${canonicalPreimageJson}`, "utf8")
    .digest("hex");
  const ledgerValue = Object.freeze({
    canonicalizationProfile: AUDIT_CANONICALIZATION_PROFILE,
    commitmentHashSha256,
    digestAlgorithm: AUDIT_DIGEST_ALGORITHM,
    eventKeyHashSha256,
    recordType,
    schemaVersion: AUDIT_COMMITMENT_SCHEMA_VERSION,
  });
  const ledgerKey = `audit~${recordType}~${eventKeyHashSha256}`;

  return Object.freeze({
    canonicalPreimageJson,
    ledgerKey,
    ledgerValue,
  });
}

function sameSha256(left, right) {
  if (!SHA256_PATTERN.test(left) || !SHA256_PATTERN.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function verifyAuditCommitment({ channelName, event, ledgerKey, ledgerValue }) {
  try {
    assertAuditLedgerValue(ledgerValue);
    const expected = buildAuditCommitment({ channelName, event });
    return ledgerKey === expected.ledgerKey
      && ledgerValue.recordType === expected.ledgerValue.recordType
      && sameSha256(ledgerValue.eventKeyHashSha256, expected.ledgerValue.eventKeyHashSha256)
      && sameSha256(ledgerValue.commitmentHashSha256, expected.ledgerValue.commitmentHashSha256);
  } catch {
    return false;
  }
}
