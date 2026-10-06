import assert from "node:assert/strict";
import test from "node:test";
import { generateDeterministicDemoEvidenceSet } from "@tenant-trust/evidence-simulators";
import {
  EVIDENCE_INGESTION_POLICY,
  EVIDENCE_STORAGE_POLICY,
  EvidenceIngestionUnavailableError,
  EvidenceRejectedError,
  canonicalizeEvidenceJson,
  createEvidenceProtector,
  createEvidenceIngestionService,
  createEvidenceStorageService,
  createInMemoryEvidenceReplayGuard,
  createPostgresEvidenceReplayGuard,
  createPostgresEvidenceVerificationResolver,
} from "../src/index.mjs";

const fixture = generateDeterministicDemoEvidenceSet();
const FIXTURE_CLOCK = () => new Date("2026-10-05T08:00:30.000Z");
const MASTER_KEY = Buffer.alloc(32, 7).toString("base64url");

function protector() {
  return createEvidenceProtector({
    masterKeyBase64Url: MASTER_KEY,
    generateIv: () => Buffer.alloc(12, 9),
  });
}

function replayGuard(clock = FIXTURE_CLOCK) {
  return createInMemoryEvidenceReplayGuard({ clock });
}

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

function replayCandidate(overrides = {}) {
  const envelope = fixture.envelopes[0];
  return {
    tenantId: envelope.tenantId,
    subjectId: envelope.subjectId,
    sourceId: envelope.sourceId,
    keyId: envelope.signature.keyId,
    evidenceType: envelope.evidenceType,
    eventId: envelope.eventId,
    sourceSequence: envelope.sourceSequence,
    nonce: envelope.nonce,
    observedAt: envelope.observedAt,
    expiresAt: envelope.expiresAt,
    contentHashSha256: envelope.signature.signedContentSha256,
    synthetic: envelope.synthetic,
    maximumAgeSeconds: 300,
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
    maximumFutureClockSkewSeconds: 30,
    replayStateScope: "tenant-source-key-epoch",
    rejectionAuditIdentifiers: "sha256",
    rawPayloadPersistence: "application-encrypted-off-chain",
  });
  assert.throws(
    () => createEvidenceIngestionService({ async resolveVerificationContext() {} }),
    /atomic evidence replay guard/u,
  );
});

test("all five deterministic evidence types verify and return bounded receipts", async () => {
  const lookups = [];
  const service = createEvidenceIngestionService({
    protectEvidence: protector().protect,
    applyReplayGuard: replayGuard(),
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

test("canonical evidence is encrypted, tenant scoped, retrievable and deletable", async () => {
  assert.deepEqual(EVIDENCE_STORAGE_POLICY, {
    formatVersion: 1,
    cipher: "AES-256-GCM",
    keyDerivation: "HKDF-SHA-256",
    ivBytes: 12,
    authenticationTagBytes: 16,
    retentionDays: 30,
    maximumCanonicalBytes: 65_536,
    accessRule: "subject-owner-or-tenant-admin",
    deletionRule: "tenant-admin",
  });
  const guard = replayGuard();
  const evidenceProtector = protector();
  const service = createEvidenceIngestionService({
    protectEvidence: evidenceProtector.protect,
    applyReplayGuard: guard,
    async resolveVerificationContext() { return contextFor(); },
  });
  await service.ingest({ envelope: fixture.envelopes[0] });

  const rawRecord = await guard.storage.retrieve({
    tenantId: fixture.tenantId,
    actorSubjectId: fixture.subjectId,
    eventId: fixture.envelopes[0].eventId,
  });
  assert.equal(rawRecord.ciphertextBase64Url.includes("identityState"), false);
  assert.equal(rawRecord.cipher, "AES-256-GCM");
  assert.equal(rawRecord.retainedUntil, "2026-11-04T08:00:30.000Z");
  const tamperedCiphertext = Buffer.from(rawRecord.ciphertextBase64Url, "base64url");
  tamperedCiphertext[0] ^= 1;
  assert.throws(
    () => evidenceProtector.unprotect({
      ...rawRecord,
      ciphertextBase64Url: tamperedCiphertext.toString("base64url"),
    }),
    EvidenceIngestionUnavailableError,
  );

  const storage = createEvidenceStorageService({ repository: guard.storage, protector: evidenceProtector });
  const ownEvidence = await storage.retrieve({
    tenantId: fixture.tenantId,
    actorSubjectId: fixture.subjectId,
    eventId: fixture.envelopes[0].eventId,
  });
  assert.equal(
    ownEvidence.canonicalBytes.toString("utf8"),
    canonicalizeEvidenceJson(fixture.envelopes[0]),
  );
  assert.deepEqual(ownEvidence.envelope, fixture.envelopes[0]);

  const otherMember = await storage.retrieve({
    tenantId: fixture.tenantId,
    actorSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
    eventId: fixture.envelopes[0].eventId,
  });
  assert.equal(otherMember, null);
  const adminEvidence = await storage.retrieve({
    tenantId: fixture.tenantId,
    actorSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
    actorIsTenantAdmin: true,
    eventId: fixture.envelopes[0].eventId,
  });
  assert.deepEqual(adminEvidence.envelope, fixture.envelopes[0]);

  assert.equal(await storage.delete({
    tenantId: fixture.tenantId,
    actorSubjectId: fixture.subjectId,
    actorIsTenantAdmin: false,
    eventId: fixture.envelopes[0].eventId,
    reason: "requested cleanup",
  }), false);
  assert.equal(await storage.delete({
    tenantId: fixture.tenantId,
    actorSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
    actorIsTenantAdmin: true,
    eventId: fixture.envelopes[0].eventId,
    reason: "requested cleanup",
  }), true);
  assert.equal(await storage.retrieve({
    tenantId: fixture.tenantId,
    actorSubjectId: fixture.subjectId,
    eventId: fixture.envelopes[0].eventId,
  }), null);
});

test("retention expiry makes ciphertext unavailable and purge creates a tombstone", async () => {
  let now = new Date("2026-10-05T08:00:30.000Z");
  const guard = replayGuard(() => new Date(now));
  const evidenceProtector = protector();
  const service = createEvidenceIngestionService({
    protectEvidence: evidenceProtector.protect,
    applyReplayGuard: guard,
    async resolveVerificationContext() { return contextFor(); },
  });
  await service.ingest({ envelope: fixture.envelopes[0] });
  now = new Date("2026-11-04T08:00:30.000Z");
  const storage = createEvidenceStorageService({ repository: guard.storage, protector: evidenceProtector });
  assert.equal(await storage.retrieve({
    tenantId: fixture.tenantId,
    actorSubjectId: fixture.subjectId,
    eventId: fixture.envelopes[0].eventId,
  }), null);
  assert.equal(await storage.purgeExpired({
    tenantId: fixture.tenantId,
    actorSubjectId: "sub_018f1234-5678-7abc-8def-0123456789ac",
    actorIsTenantAdmin: true,
  }), 1);
});

test("schema and size failures are rejected before authoritative lookup", async () => {
  let lookups = 0;
  const service = createEvidenceIngestionService({
    protectEvidence: protector().protect,
    applyReplayGuard: replayGuard(),
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
      protectEvidence: protector().protect,
      applyReplayGuard: replayGuard(),
      async resolveVerificationContext() { return resolved; },
    });
    await assert.rejects(service.ingest({ envelope: fixture.envelopes[0] }), EvidenceRejectedError);
  }
});

test("tampering, digest replacement and a different source key cannot authenticate", async () => {
  const service = createEvidenceIngestionService({
    protectEvidence: protector().protect,
    applyReplayGuard: replayGuard(),
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
    protectEvidence: protector().protect,
    applyReplayGuard: replayGuard(),
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

test("freshness guard enforces clock skew, expiry and the source TTL", async () => {
  const guard = replayGuard(() => new Date("2026-10-05T08:05:00.000Z"));
  const cases = [
    [{ observedAt: "2026-10-05T08:05:31.000Z", expiresAt: "2026-10-05T08:06:00.000Z" }, "EVIDENCE_OBSERVED_IN_FUTURE"],
    [{ observedAt: "2026-10-05T07:59:59.000Z", expiresAt: "2026-10-05T08:05:30.000Z" }, "EVIDENCE_STALE"],
    [{ observedAt: "2026-10-05T08:03:00.000Z", expiresAt: "2026-10-05T08:04:59.999Z" }, "EVIDENCE_EXPIRED"],
    [{ observedAt: "2026-10-05T08:05:00.000Z", expiresAt: "2026-10-05T08:10:01.000Z" }, "EVIDENCE_TTL_EXCEEDED"],
    [{ observedAt: "2026-10-05T08:05:00.000Z", expiresAt: "2026-10-05T08:05:00.000Z" }, "EVIDENCE_TIME_WINDOW_INVALID"],
  ];
  for (const [overrides, reasonCode] of cases) {
    const decision = await guard(replayCandidate(overrides));
    assert.equal(decision.accepted, false);
    assert.equal(decision.reasonCode, reasonCode);
  }

  const boundary = await replayGuard(() => new Date("2026-10-05T08:05:00.000Z"))(
    replayCandidate({
      observedAt: "2026-10-05T08:05:30.000Z",
      expiresAt: "2026-10-05T08:06:00.000Z",
    }),
  );
  assert.equal(boundary.accepted, true);
});

test("replay guard rejects duplicate IDs, nonces, sequences and older observations", async () => {
  const guard = replayGuard(() => new Date("2026-10-05T08:05:00.000Z"));
  const accepted = replayCandidate({
    eventId: "evt_018f1234-5678-7abc-8def-0123456789e0",
    sourceSequence: 10,
    nonce: "AAAAAAAAAAAAAAAAAAAAAA",
    observedAt: "2026-10-05T08:05:00.000Z",
    expiresAt: "2026-10-05T08:10:00.000Z",
  });
  assert.equal((await guard(accepted)).accepted, true);

  const scenarios = [
    [accepted, "EVIDENCE_EVENT_REPLAYED"],
    [{ ...accepted, eventId: "evt_018f1234-5678-7abc-8def-0123456789e1", sourceSequence: 11 }, "EVIDENCE_NONCE_REPLAYED"],
    [{ ...accepted, eventId: "evt_018f1234-5678-7abc-8def-0123456789e2", nonce: "BBBBBBBBBBBBBBBBBBBBBB" }, "EVIDENCE_SEQUENCE_REPLAYED"],
    [{ ...accepted, eventId: "evt_018f1234-5678-7abc-8def-0123456789e3", nonce: "CCCCCCCCCCCCCCCCCCCCCC", sourceSequence: 9 }, "EVIDENCE_SEQUENCE_REORDERED"],
    [{ ...accepted, eventId: "evt_018f1234-5678-7abc-8def-0123456789e4", nonce: "DDDDDDDDDDDDDDDDDDDDDD", sourceSequence: 11, observedAt: "2026-10-05T08:04:59.999Z", expiresAt: "2026-10-05T08:09:59.999Z" }, "EVIDENCE_OBSERVATION_REORDERED"],
  ];
  for (const [candidate, reasonCode] of scenarios) {
    const decision = await guard(candidate);
    assert.equal(decision.accepted, false);
    assert.equal(decision.reasonCode, reasonCode);
    assert.equal(decision.highestSourceSequence, 10);
  }

  const newKeyEpoch = await guard({
    ...accepted,
    keyId: "key_018f1234-5678-7abc-8def-0123456789e5",
    eventId: "evt_018f1234-5678-7abc-8def-0123456789e5",
    sourceSequence: 0,
  });
  assert.equal(newKeyEpoch.accepted, true);

  const snapshot = guard.snapshot();
  assert.equal(snapshot.totalRejections, 5);
  assert.deepEqual(snapshot.byReason, {
    EVIDENCE_EVENT_REPLAYED: 1,
    EVIDENCE_NONCE_REPLAYED: 1,
    EVIDENCE_SEQUENCE_REPLAYED: 1,
    EVIDENCE_SEQUENCE_REORDERED: 1,
    EVIDENCE_OBSERVATION_REORDERED: 1,
  });
  assert.equal(JSON.stringify(snapshot.records).includes(accepted.eventId), false);
  assert.equal(JSON.stringify(snapshot.records).includes(accepted.nonce), false);
  assert.match(snapshot.records[0].eventIdSha256, /^[0-9a-f]{64}$/u);
});

test("per-source flood controls cap influence and automatically suspend a noisy source", async () => {
  const guard = createInMemoryEvidenceReplayGuard({
    clock: () => new Date("2026-10-05T08:05:00.000Z"),
    safeguards: {
      rateLimitWindowSeconds: 60,
      rateLimitMaxEvents: 2,
      rateLimitSuspensionThreshold: 2,
      maximumInfluence: 0.4,
      tenantMaximumSourceInfluence: 0.2,
    },
  });
  const candidates = [
    ["e0", 1, "AAAAAAAAAAAAAAAAAAAAAA"],
    ["e1", 2, "BBBBBBBBBBBBBBBBBBBBBB"],
    ["e2", 3, "CCCCCCCCCCCCCCCCCCCCCC"],
    ["e3", 4, "DDDDDDDDDDDDDDDDDDDDDD"],
    ["e4", 5, "EEEEEEEEEEEEEEEEEEEEEE"],
  ].map(([suffix, sourceSequence, nonce]) => replayCandidate({
    eventId: `evt_018f1234-5678-7abc-8def-0123456789${suffix}`,
    sourceSequence,
    nonce,
    observedAt: "2026-10-05T08:04:55.000Z",
    expiresAt: "2026-10-05T08:09:55.000Z",
  }));

  assert.equal((await guard(candidates[0])).accepted, true);
  assert.equal((await guard(candidates[1])).accepted, true);
  assert.equal((await guard(candidates[2])).reasonCode, "EVIDENCE_RATE_LIMITED");
  assert.equal((await guard(candidates[3])).reasonCode, "EVIDENCE_RATE_LIMITED");
  assert.equal((await guard(candidates[4])).reasonCode, "VERIFICATION_CONTEXT_NOT_FOUND");

  const sourceControl = guard.snapshot().sourceControls[0];
  assert.equal(sourceControl.acceptedCount, 2);
  assert.equal(sourceControl.rateLimitedCount, 2);
  assert.equal(sourceControl.suspended, true);
  assert.equal(sourceControl.maximumSourceInfluence, 0.2);
});

test("ingestion rejects a replay after signature verification", async () => {
  const guard = replayGuard();
  const service = createEvidenceIngestionService({
    protectEvidence: protector().protect,
    applyReplayGuard: guard,
    async resolveVerificationContext() { return contextFor(); },
  });
  await service.ingest({ envelope: fixture.envelopes[0] });
  await assert.rejects(
    service.ingest({ envelope: fixture.envelopes[0] }),
    (error) => error instanceof EvidenceRejectedError
      && error.reasonCode === "EVIDENCE_EVENT_REPLAYED",
  );
  assert.equal(guard.snapshot().byReason.EVIDENCE_EVENT_REPLAYED, 1);
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

test("PostgreSQL replay guard commits one atomic decision with bounded metadata", async () => {
  const calls = [];
  let released = false;
  const guard = createPostgresEvidenceReplayGuard({
    pool: {
      async connect() {
        return {
          async query(input) {
            calls.push(input);
            if (input.text.includes("apply_evidence_replay_guard")) {
              return {
                rowCount: 1,
                rows: [{
                  accepted: true,
                  reason_code: null,
                  accepted_at: new Date("2026-10-05T08:00:30.000Z"),
                  highest_source_sequence: "1",
                }],
              };
            }
            if (input.text.includes("store_encrypted_evidence")) {
              return { rowCount: 1, rows: [{ retained_until: new Date("2026-11-04T08:00:30.000Z") }] };
            }
            return { rowCount: null, rows: [] };
          },
          release() { released = true; },
        };
      },
    },
  });
  const candidate = replayCandidate({
    protectedEvidence: protector().protect({
      envelope: fixture.envelopes[0],
      contentHashSha256: fixture.envelopes[0].signature.signedContentSha256,
    }),
  });
  const decision = await guard(candidate);
  const guarded = calls.find(({ text }) => text.includes("apply_evidence_replay_guard"));
  assert.deepEqual(guarded.values, [
    candidate.tenantId,
    candidate.subjectId,
    candidate.sourceId,
    candidate.keyId,
    candidate.evidenceType,
    candidate.eventId,
    candidate.sourceSequence,
    candidate.nonce,
    candidate.observedAt,
    candidate.expiresAt,
    candidate.contentHashSha256,
    candidate.synthetic,
  ]);
  assert.deepEqual(decision, {
    accepted: true,
    reasonCode: null,
    acceptedAt: "2026-10-05T08:00:30.000Z",
    highestSourceSequence: 1,
  });
  const stored = calls.find(({ text }) => text.includes("store_encrypted_evidence"));
  assert.equal(stored.values[0], candidate.tenantId);
  assert.equal(stored.values[1], candidate.eventId);
  assert.equal(Buffer.isBuffer(stored.values[4]), true);
  assert.equal(Buffer.isBuffer(stored.values[6]), true);
  assert.equal(calls.at(-1).text, "COMMIT");
  assert.equal(released, true);
});
