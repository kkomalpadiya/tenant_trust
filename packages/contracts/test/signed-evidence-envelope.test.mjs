import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaRoot = fileURLToPath(new URL("../schemas/", import.meta.url));
const common = JSON.parse(readFileSync(`${schemaRoot}/common.schema.json`, "utf8"));
const schema = JSON.parse(readFileSync(`${schemaRoot}/evidence/signed-evidence-envelope.schema.json`, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validate = ajv.compile(schema);

const ids = {
  event: "evt_018f1234-5678-7abc-8def-0123456789ab",
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  source: "src_018f1234-5678-7abc-8def-0123456789ab"
};

function envelope(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    eventId: ids.event,
    tenantId: ids.tenant,
    subjectId: ids.subject,
    sourceId: ids.source,
    evidenceType: "device",
    observedAt: "2026-10-05T08:00:00.000Z",
    expiresAt: "2026-10-05T08:05:00.000Z",
    sourceSequence: 42,
    nonce: "QWxwaGEtdGVzdC1ub25jZQ",
    synthetic: true,
    payload: {
      posture: "managed",
      diskEncryption: true,
      patchAgeDays: 2
    },
    signature: {
      algorithm: "Ed25519",
      canonicalization: "tenant-trust-evidence-json-v1",
      keyId: "tenant-alpha/device-source/key-2026-01",
      signedContentSha256: "ab".repeat(32),
      signatureBase64Url: "A".repeat(86)
    },
    ...overrides
  };
}

test("the signed evidence envelope accepts every supported evidence type", () => {
  for (const evidenceType of ["identity", "device", "behaviour", "certificate", "compliance"]) {
    const candidate = envelope({ evidenceType });
    assert.equal(validate(candidate), true, `${evidenceType}: ${ajv.errorsText(validate.errors)}`);
  }
});

test("the envelope requires every identity, freshness, ordering and signature field", () => {
  for (const field of [
    "schemaVersion",
    "eventId",
    "tenantId",
    "subjectId",
    "sourceId",
    "observedAt",
    "expiresAt",
    "sourceSequence",
    "nonce",
    "signature"
  ]) {
    const candidate = envelope();
    delete candidate[field];
    assert.equal(validate(candidate), false, `${field} was unexpectedly optional`);
  }
});

test("signature metadata is exact and rejects weak or ambiguous representations", () => {
  const invalidSignatures = [
    { ...envelope().signature, algorithm: "RS256" },
    { ...envelope().signature, canonicalization: "JSON.stringify" },
    { ...envelope().signature, keyId: "short" },
    { ...envelope().signature, signedContentSha256: "AB".repeat(32) },
    { ...envelope().signature, signatureBase64Url: "A".repeat(88) },
    { ...envelope().signature, unexpected: true }
  ];
  for (const signature of invalidSignatures) assert.equal(validate(envelope({ signature })), false);
});

test("identifiers, UTC timestamps, sequence and nonce use canonical bounded forms", () => {
  const invalidCandidates = [
    envelope({ eventId: "event-1" }),
    envelope({ tenantId: "tenant-alpha" }),
    envelope({ subjectId: "subject-alice" }),
    envelope({ sourceId: "source-device" }),
    envelope({ observedAt: "2026-10-05T13:30:00+05:30" }),
    envelope({ expiresAt: "2026-10-05 08:05:00" }),
    envelope({ sourceSequence: -1 }),
    envelope({ sourceSequence: 1.5 }),
    envelope({ nonce: "too-short" })
  ];
  for (const candidate of invalidCandidates) assert.equal(validate(candidate), false);
});

test("the contract keeps the signed surface closed while allowing typed evidence payloads", () => {
  assert.equal(validate(envelope({ unexpected: true })), false);
  assert.equal(validate(envelope({ payload: {} })), false);
  assert.equal(validate(envelope({ evidenceType: "location" })), false);
  assert.equal(validate(envelope({ payload: { certificateState: "active", serial: "01AF" } })), true);
});
