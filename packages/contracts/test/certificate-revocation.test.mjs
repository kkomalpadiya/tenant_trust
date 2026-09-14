import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaRoot = fileURLToPath(new URL("../schemas/", import.meta.url));
const common = JSON.parse(readFileSync(`${schemaRoot}/common.schema.json`, "utf8"));
const schema = JSON.parse(readFileSync(`${schemaRoot}/pki/certificate-revocation-request.schema.json`, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validate = ajv.compile(schema);

const request = {
  requestId: "req_018f1234-5678-7abc-8def-0123456789ab",
  certificateId: "crt_018f1234-5678-7abc-8def-0123456789ab",
  reasonCode: "KEY_COMPROMISE",
  idempotencyKey: "tenant-alpha:certificate:revoke:0001",
};

test("the revocation request accepts only the target, approved reason and retry identities", () => {
  assert.equal(validate(request), true, ajv.errorsText(validate.errors));
  for (const candidate of [
    { ...request, reasonCode: "CERTIFICATE_HOLD" },
    { ...request, tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab" },
    { ...request, issuerId: "iss_018f1234-5678-7abc-8def-0123456789ab" },
    { ...request, reasonCode: null },
  ]) assert.equal(validate(candidate), false);
});
