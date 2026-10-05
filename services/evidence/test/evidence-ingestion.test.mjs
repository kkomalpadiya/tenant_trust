import assert from "node:assert/strict";
import test from "node:test";
import { generateDeterministicDemoEvidenceSet } from "@tenant-trust/evidence-simulators";
import {
  EVIDENCE_INGESTION_POLICY,
  EvidenceIngestionUnavailableError,
  EvidenceRejectedError,
  createEvidenceIngestionService,
  createPostgresEvidenceVerificationResolver,
} from "../src/index.mjs";

const fixture = generateDeterministicDemoEvidenceSet();

function contextFor(index = 0, overrides = {}) {
  const envelope = fixture.envelopes[index];
  const enrollment = fixture.enrollments[index];
  return {
    tenantId: envelope.tenantId,
    subjectId: envelope.subjectId,
    sourceId: envelope.sourceId,
    evidenceType: envelope.evidenceType,
    sourceSynthetic: envelope.synthetic,
    maximumAgeSeconds: [300, 300, 300, 60, 3600][index],
    sourceState: "active",
    verificationAlgorithm: "Ed25519",
    keyId: enrollment.keyId,
    keyState: "active",
    keyVersion: 1,
    publicKeyBase64Url: enrollment.publicKeyBase64Url,
    publicKeySha256: enrollment.publicKeySha256,
    keyEnrolledAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

test("ingestion policy fixes the endpoint, size and cryptographic boundary", () => {
  assert.deepEqual(EVIDENCE_INGESTION_POLICY, {
    schemaVersion: "1.0.0",
    endpoint: "/v1/evidence",
    maximumEnvelopeBytes: 65_536,
    maximumPayloadBytes: 32_768,
    signatureAlgorithm: "Ed25519",
    canonicalizationProfile: "tenant-trust-evidence-json-v1",
    acceptedSourceState: "active",
    acceptedKeyState: "active",
    rawPayloadPersistence: false,
  });
});

test("all five deterministic evidence types verify and return bounded receipts", async () => {
  const lookups = [];
  const service = createEvidenceIngestionService({
    async resolveVerificationContext(binding) {
      lookups.push(binding);
      return contextFor(fixture.envelopes.findIndex((item) => item.sourceId === binding.sourceId));
    },
  });

  for (const envelope of fixture.envelopes) {
    const receipt = await service.ingest({ envelope });
    assert.equal(receipt.status, "accepted");
    assert.equal(receipt.eventId, envelope.eventId);
    assert.equal(receipt.tenantId, envelope.tenantId);
    assert.equal(receipt.subjectId, envelope.subjectId);
    assert.equal(receipt.sourceId, envelope.sourceId);
    assert.equal(receipt.evidenceType, envelope.evidenceType);
    assert.equal(receipt.sourceSequence, envelope.sourceSequence);
    assert.equal(receipt.synthetic, true);
    assert.equal(receipt.contentHashSha256, envelope.signature.signedContentSha256);
    assert.deepEqual(Object.keys(receipt).sort(), [
      "contentHashSha256",
      "eventId",
      "evidenceType",
      "sourceId",
      "sourceSequence",
      "status",
      "subjectId",
      "synthetic",
      "tenantId",
    ]);
    assert.equal(Object.isFrozen(receipt), true);
  }
  assert.deepEqual(lookups[0], {
    tenantId: fixture.tenantId,
    subjectId: fixture.subjectId,
    sourceId: fixture.envelopes[0].sourceId,
    keyId: fixture.enrollments[0].keyId,
  });
});

test("schema and size failures are rejected before authoritative lookup", async () => {
  let lookups = 0;
  const service = createEvidenceIngestionService({
    async resolveVerificationContext() {
      lookups += 1;
      return contextFor();
    },
  });
  await assert.rejects(
    service.ingest({ envelope: { ...fixture.envelopes[0], callerSelectedTenant: "forged" } }),
    (error) => error instanceof EvidenceRejectedError && error.reasonCode === "EVIDENCE_SCHEMA_INVALID",
  );
  await assert.rejects(
    service.ingest({
      envelope: fixture.envelopes[0],
      encodedByteLength: EVIDENCE_INGESTION_POLICY.maximumEnvelopeBytes + 1,
    }),
    (error) => error instanceof EvidenceRejectedError && error.reasonCode === "EVIDENCE_TOO_LARGE",
  );
  const oversizedPayload = structuredClone(fixture.envelopes[0]);
  oversizedPayload.payload = { claim: "x".repeat(EVIDENCE_INGESTION_POLICY.maximumPayloadBytes + 1) };
  await assert.rejects(
    service.ingest({ envelope: oversizedPayload }),
    (error) => error instanceof EvidenceRejectedError && error.reasonCode === "EVIDENCE_TOO_LARGE",
  );
  assert.equal(lookups, 0);
});

test("missing, inactive and cross-bound verification tuples fail closed", async () => {
  for (const resolved of [
    null,
    contextFor(0, { sourceState: "suspended" }),
    contextFor(0, { tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ac" }),
    contextFor(0, { subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad" }),
    contextFor(0, { sourceSynthetic: false }),
  ]) {
    const service = createEvidenceIngestionService({
      async resolveVerificationContext() { return resolved; },
    });
    await assert.rejects(service.ingest({ envelope: fixture.envelopes[0] }), EvidenceRejectedError);
  }
});

test("tampering, digest replacement and a different source key cannot authenticate", async () => {
  const service = createEvidenceIngestionService({
    async resolveVerificationContext() { return contextFor(); },
  });
  const tampered = structuredClone(fixture.envelopes[0]);
  tampered.payload.identityState = "disabled";
  await assert.rejects(
    service.ingest({ envelope: tampered }),
    (error) => error instanceof EvidenceRejectedError
      && error.reasonCode === "SIGNED_CONTENT_DIGEST_INVALID",
  );

  const forgedDigest = structuredClone(fixture.envelopes[0]);
  forgedDigest.signature.signedContentSha256 = "0".repeat(64);
  await assert.rejects(service.ingest({ envelope: forgedDigest }), EvidenceRejectedError);

  const beta = generateDeterministicDemoEvidenceSet({ tenantAlias: "beta" });
  const wrongKeyService = createEvidenceIngestionService({
    async resolveVerificationContext() {
      return contextFor(0, {
        publicKeyBase64Url: beta.enrollments[0].publicKeyBase64Url,
        publicKeySha256: beta.enrollments[0].publicKeySha256,
      });
    },
  });
  await assert.rejects(
    wrongKeyService.ingest({ envelope: fixture.envelopes[0] }),
    (error) => error instanceof EvidenceRejectedError
      && error.reasonCode === "EVIDENCE_SIGNATURE_INVALID",
  );
});

test("PostgreSQL resolver parameterizes the exact tuple without binding claimed actor authority", async () => {
  const calls = [];
  let released = false;
  const enrollment = fixture.enrollments[0];
  const resolver = createPostgresEvidenceVerificationResolver({
    pool: {
      async connect() {
        return {
          async query(input) {
            calls.push(input);
            if (input.text.includes("resolve_evidence_verification_context")) {
              return {
                rowCount: 1,
                rows: [{
                  tenant_id: fixture.tenantId,
                  subject_id: fixture.subjectId,
                  source_id: enrollment.sourceId,
                  evidence_type: enrollment.evidenceType,
                  source_synthetic: true,
                  maximum_age_seconds: 300,
                  source_state: "active",
                  verification_algorithm: "Ed25519",
                  key_id: enrollment.keyId,
                  key_state: "active",
                  key_version: 1,
                  public_key_base64url: enrollment.publicKeyBase64Url,
                  public_key_sha256: enrollment.publicKeySha256,
                  key_enrolled_at: new Date("2026-01-01T00:00:00.000Z"),
                }],
              };
            }
            return { rowCount: null, rows: [] };
          },
          release() { released = true; },
        };
      },
    },
  });
  const binding = {
    tenantId: fixture.tenantId,
    subjectId: fixture.subjectId,
    sourceId: enrollment.sourceId,
    keyId: enrollment.keyId,
  };
  const context = await resolver(binding);
  const lookup = calls.find(({ text }) => text.includes("resolve_evidence_verification_context"));
  assert.deepEqual(lookup.values, Object.values(binding));
  assert.equal(calls.some(({ text }) => text.includes("set_tenant_actor_context")), false);
  assert.equal(context.publicKeyBase64Url, enrollment.publicKeyBase64Url);
  assert.equal(context.keyEnrolledAt, "2026-01-01T00:00:00.000Z");
  assert.equal(calls.at(-1).text, "COMMIT");
  assert.equal(released, true);
});

test("PostgreSQL resolver rolls back and exposes only an availability failure", async () => {
  const calls = [];
  let released = false;
  const resolver = createPostgresEvidenceVerificationResolver({
    pool: {
      async connect() {
        return {
          async query(input) {
            const text = typeof input === "string" ? input : input.text;
            calls.push(text);
            if (text.includes("resolve_evidence_verification_context")) {
              throw new Error("database detail must not escape");
            }
            return { rowCount: null, rows: [] };
          },
          release() { released = true; },
        };
      },
    },
  });
  await assert.rejects(resolver({
    tenantId: fixture.tenantId,
    subjectId: fixture.subjectId,
    sourceId: fixture.enrollments[0].sourceId,
    keyId: fixture.enrollments[0].keyId,
  }), EvidenceIngestionUnavailableError);
  assert.equal(calls.at(-1), "ROLLBACK");
  assert.equal(released, true);
});
