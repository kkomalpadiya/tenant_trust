import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaRoot = fileURLToPath(new URL("../schemas/", import.meta.url));
const common = JSON.parse(readFileSync(`${schemaRoot}/common.schema.json`, "utf8"));
const requestSchema = JSON.parse(readFileSync(`${schemaRoot}/pki/certificate-request.schema.json`, "utf8"));
const profile = JSON.parse(readFileSync(`${schemaRoot}/pki/certificate-identity-profile.json`, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateRequest = ajv.compile(requestSchema);

const ids = {
  tenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  subject: "sub_018f1234-5678-7abc-8def-0123456789ab",
  admin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  request: "req_018f1234-5678-7abc-8def-0123456789ab",
  certificate: "crt_018f1234-5678-7abc-8def-0123456789ab"
};
const csrBody = "A".repeat(96);

function request(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    requestId: ids.request,
    profileId: "tenant-client-auth-v1",
    operation: "issue",
    tenantId: ids.tenant,
    subjectId: ids.subject,
    requestedBySubjectId: ids.admin,
    requestedAt: "2026-09-12T12:00:00.000Z",
    requestedValiditySeconds: 3600,
    proofOfPossession: {
      publicKeyAlgorithm: "ecdsa-p256",
      csrPem: `-----BEGIN CERTIFICATE REQUEST-----\n${csrBody}\n-----END CERTIFICATE REQUEST-----\n`,
      csrSha256: "ab".repeat(32)
    },
    renewalOfCertificateId: null,
    idempotencyKey: "tenant-alpha:certificate:issue:0001",
    ...overrides
  };
}

test("the normalized issuance request compiles and accepts the supported profile", () => {
  const candidate = request();
  assert.equal(validateRequest(candidate), true, ajv.errorsText(validateRequest.errors));
});

test("issue and renewal requests have explicit, different certificate lineage", () => {
  const issuance = request();
  assert.equal(validateRequest(issuance), true);

  const renewal = request({ operation: "renew", renewalOfCertificateId: ids.certificate });
  assert.equal(validateRequest(renewal), true, ajv.errorsText(validateRequest.errors));

  assert.equal(validateRequest(request({ renewalOfCertificateId: ids.certificate })), false);
  assert.equal(validateRequest(request({ operation: "renew", renewalOfCertificateId: null })), false);
});

test("callers cannot select an issuer or inject certificate identity and privilege fields", () => {
  for (const [field, value] of [
    ["issuerId", "iss_018f1234-5678-7abc-8def-0123456789ab"],
    ["authorityUrl", "https://issuer.tenant-beta.invalid"],
    ["subject", { commonName: "administrator" }],
    ["subjectAlternativeNames", ["urn:foreign-tenant"]],
    ["keyUsage", ["keyCertSign"]],
    ["extendedKeyUsage", ["serverAuth"]],
    ["serialNumber", "01".repeat(16)],
    ["notAfter", "2036-09-12T12:00:00.000Z"],
    ["privateKey", "not-accepted"]
  ]) {
    assert.equal(validateRequest(request({ [field]: value })), false, `${field} was unexpectedly accepted`);
  }
});

test("request validation constrains time, algorithm and proof-of-possession shape", () => {
  const invalidCandidates = [
    request({ profileId: "tenant-client-auth-v2" }),
    request({ requestedAt: "2026-09-12T17:30:00+05:30" }),
    request({ requestedValiditySeconds: 299 }),
    request({ requestedValiditySeconds: 86401 }),
    request({ proofOfPossession: { ...request().proofOfPossession, publicKeyAlgorithm: "rsa-1024" } }),
    request({ proofOfPossession: { ...request().proofOfPossession, csrPem: "not-a-csr" } }),
    request({ proofOfPossession: { ...request().proofOfPossession, csrSha256: "AB".repeat(32) } })
  ];
  for (const candidate of invalidCandidates) assert.equal(validateRequest(candidate), false);
});

test("the identity profile binds opaque tenant and subject IDs without mutable roles", () => {
  assert.equal(profile.profileId, "tenant-client-auth-v1");
  assert.deepEqual(profile.identity.subject.relativeDistinguishedNames, [
    { attribute: "commonName", source: "subjectId" },
    { attribute: "organizationName", source: "tenantId" }
  ]);
  assert.equal(profile.identity.subject.humanReadableIdentityAllowed, false);
  assert.deepEqual(profile.identity.subjectAlternativeNames.required, [{
    type: "uniformResourceIdentifier",
    template: "urn:tenant-trust:identity:v1:tenant:{tenantId}:subject:{subjectId}"
  }]);
  assert.equal(profile.identity.subjectAlternativeNames.callerSuppliedValuesAccepted, false);
  assert.deepEqual(profile.identity.subjectAlternativeNames.forbiddenTypes, ["dNSName", "iPAddress", "rfc822Name"]);
  assert.equal(JSON.stringify(profile.identity).includes("role"), false);
});

test("the profile is a non-CA client-auth certificate with bounded keys, serials and validity", () => {
  assert.deepEqual(profile.extensions.basicConstraints, { critical: true, ca: false });
  assert.deepEqual(profile.extensions.keyUsage, { critical: true, values: ["digitalSignature"] });
  assert.deepEqual(profile.extensions.extendedKeyUsage, { critical: false, values: ["clientAuth"] });
  assert.deepEqual(profile.publicKey.allowedAlgorithms, ["ecdsa-p256", "ed25519"]);
  assert.equal(profile.publicKey.minimumSecurityBits, 128);
  assert.equal(profile.publicKey.proofOfPossession, "pkcs10-signature");

  assert.deepEqual(profile.serialNumber, {
    source: "issuing-ca",
    callerSupplied: false,
    randomBits: 128,
    encoding: "uppercase-hex",
    encodedLength: 32,
    nonZero: true,
    uniquenessScope: "issuer"
  });
  assert.deepEqual(profile.validity, {
    requestedValiditySecondsMinimum: 300,
    requestedValiditySecondsDefault: 3600,
    requestedValiditySecondsMaximum: 86400,
    backdateSeconds: 60,
    notBeforeRule: "issued-at-minus-backdate",
    notAfterRule: "not-before-plus-requested-validity",
    renewalMayExceedMaximum: false
  });
  assert.equal(profile.requestBoundary.issuerSelection, "validated-tenant-context");
  assert.ok(profile.requestBoundary.forbiddenCallerFields.includes("privateKey"));
});
