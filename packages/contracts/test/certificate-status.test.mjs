import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaRoot = fileURLToPath(new URL("../schemas/", import.meta.url));
const common = JSON.parse(readFileSync(`${schemaRoot}/common.schema.json`, "utf8"));
const statusSchema = JSON.parse(readFileSync(`${schemaRoot}/pki/certificate-status.schema.json`, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validate = ajv.compile(statusSchema);

const active = {
  schemaVersion: "1.0.0",
  mechanism: "application-status-v1",
  outcome: "accept",
  reasonCode: "CERTIFICATE_ACTIVE",
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subjectId: "sub_018f1234-5678-7abc-8def-0123456789ab",
  certificateId: "crt_018f1234-5678-7abc-8def-0123456789ab",
  issuerId: "iss_018f1234-5678-7abc-8def-0123456789ab",
  serialNumber: "00000000000000000000000000000001",
  fingerprintSha256: "ab".repeat(32),
  inventoryState: "active",
  sourceStatus: "authoritative",
  statusVersion: 1,
  statusObservedAt: "2026-09-14T10:00:00.000Z",
  checkedAt: "2026-09-14T10:00:01.000Z",
  cacheableUntil: "2026-09-14T10:00:30.000Z"
};

test("the application-status contract accepts a fresh authoritative active verdict", () => {
  assert.equal(validate(active), true, ajv.errorsText(validate.errors));
});

test("accept cannot describe a revoked state, stale source or missing cache deadline", () => {
  for (const candidate of [
    { ...active, inventoryState: "revoked" },
    { ...active, sourceStatus: "stale" },
    { ...active, cacheableUntil: null },
    { ...active, reasonCode: "CERTIFICATE_REVOKED" },
  ]) assert.equal(validate(candidate), false);
});

test("denials are explicitly non-cacheable", () => {
  const denial = {
    ...active,
    outcome: "deny",
    reasonCode: "STATUS_SOURCE_UNAVAILABLE",
    inventoryState: "unknown",
    sourceStatus: "unavailable",
    statusVersion: null,
    statusObservedAt: null,
    cacheableUntil: null,
  };
  assert.equal(validate(denial), true, ajv.errorsText(validate.errors));
  denial.cacheableUntil = "2026-09-14T10:00:30.000Z";
  assert.equal(validate(denial), false);
});
