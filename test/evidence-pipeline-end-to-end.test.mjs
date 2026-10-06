import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign as ed25519Sign,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createEvidenceIngestionService,
  createEvidenceProtector,
  createInMemoryEvidenceReplayGuard,
  EvidenceRejectedError,
} from "@tenant-trust/evidence";
import {
  createEvidenceAcceptedConsumer,
  createEvidenceAcceptedPublisher,
  EvidenceEventError,
  verifyEvidenceAcceptedEvent,
} from "@tenant-trust/evidence-events";
import {
  DEMO_EVIDENCE_SOURCE_CATALOG,
  generateAdversarialEvidenceFixtureSet,
  generateDeterministicDemoEvidenceSet,
} from "@tenant-trust/evidence-simulators";
import { EVENT_STREAM } from "@tenant-trust/messaging";
import { resolveTenantContext } from "@tenant-trust/tenant-context";

const REQUIRED_EVIDENCE_TYPES = Object.freeze([
  "identity",
  "device",
  "behaviour",
  "certificate",
  "compliance",
]);
const EVIDENCE_MASTER_KEY = Buffer.alloc(32, 7).toString("base64url");
const EVENT_SIGNING_KEY_ID = "evidence-events:e2e-key-2026-01";
const EVENT_PRODUCER = Object.freeze({ service: "evidence-events", instanceId: "e2e-verifier" });
const { privateKey: eventPrivateKey, publicKey: eventPublicKey } = generateKeyPairSync("ed25519");

const schemaRoot = resolve(import.meta.dirname, "../packages/contracts/schemas");
const commonSchema = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const evidenceEventSchema = JSON.parse(
  readFileSync(resolve(schemaRoot, "events/evidence-event.schema.json"), "utf8"),
);
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(commonSchema);
const validateEvidenceEvent = ajv.compile(evidenceEventSchema);

function uuidFor(label) {
  const bytes = Buffer.from(createHash("sha256").update(label, "utf8").digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function maximumAgeFor(sourceId) {
  for (const tenant of Object.values(DEMO_EVIDENCE_SOURCE_CATALOG)) {
    const source = tenant.sources.find((candidate) => candidate.sourceId === sourceId);
    if (source) return source.maximumAgeSeconds;
  }
  throw new Error(`No simulator source policy exists for ${sourceId}.`);
}

function contextFor(tenantId, subjectId) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId: `evidence-e2e:${tenantId}:${subjectId}`,
      tenantId,
      subjectId,
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId, state: "active", version: 1 },
      membership: { tenantId, subjectId, state: "active", version: 1 },
      roles: ["tenant-member"],
    },
  });
}

function outboxClaim(receipt, envelope, acceptedAt) {
  const identity = `${receipt.tenantId}:${receipt.eventId}`;
  return Object.freeze({
    tenantId: receipt.tenantId,
    subjectId: receipt.subjectId,
    sourceId: receipt.sourceId,
    evidenceId: `evd_${uuidFor(`evidence:${identity}`)}`,
    eventId: `evt_${uuidFor(`delivery:${identity}`)}`,
    sourceEventId: receipt.eventId,
    correlationId: `cor_${uuidFor(`correlation:${identity}`)}`,
    evidenceType: receipt.evidenceType,
    sourceSequence: receipt.sourceSequence,
    contentHashSha256: receipt.contentHashSha256,
    synthetic: receipt.synthetic,
    observedAt: envelope.observedAt,
    expiresAt: envelope.expiresAt,
    acceptedAt,
    claimToken: `clm_${uuidFor(`claim:${identity}`)}`,
    attemptCount: 1,
  });
}

function createMemoryStream() {
  const messages = new Map();
  let nextSequence = 1;
  return Object.freeze({
    async publish({ subject, payload, messageId }) {
      const existing = messages.get(messageId);
      if (existing) {
        return { stream: EVENT_STREAM, sequence: existing.sequence, duplicate: true };
      }
      const record = Object.freeze({
        subject,
        payload: Buffer.from(payload),
        event: JSON.parse(Buffer.from(payload).toString("utf8")),
        messageId,
        sequence: nextSequence,
      });
      nextSequence += 1;
      messages.set(messageId, record);
      return { stream: EVENT_STREAM, sequence: record.sequence, duplicate: false };
    },
    get size() {
      return messages.size;
    },
    get(messageId) {
      return messages.get(messageId) ?? null;
    },
  });
}

function createSecurityStateConsumer() {
  const processedEventIds = new Set();
  const stagedBySubject = new Map();
  const securityState = new Map();

  const applyVerifiedEffect = async ({ event }) => {
    const subjectScope = `${event.tenantId}:${event.subjectId}`;
    const staged = stagedBySubject.get(subjectScope) ?? new Map();
    staged.set(event.payload.evidenceType, Object.freeze({
      eventId: event.eventId,
      evidenceId: event.aggregateId,
      contentHashSha256: event.payload.contentHashSha256,
    }));
    stagedBySubject.set(subjectScope, staged);

    if (!REQUIRED_EVIDENCE_TYPES.every((type) => staged.has(type))) return;
    const evidenceEventIds = REQUIRED_EVIDENCE_TYPES.map((type) => staged.get(type).eventId);
    const previous = securityState.get(subjectScope);
    if (previous && previous.evidenceEventIds.every((eventId, index) => eventId === evidenceEventIds[index])) {
      return;
    }
    securityState.set(subjectScope, Object.freeze({
      revision: (previous?.revision ?? 0) + 1,
      evidenceTypes: [...REQUIRED_EVIDENCE_TYPES],
      evidenceEventIds,
    }));
  };

  const consumer = createEvidenceAcceptedConsumer({
    consumerName: "trust-engine.e2e-v1",
    verifyEvent: (options) => verifyEvidenceAcceptedEvent({
      ...options,
      validateEvent: validateEvidenceEvent,
    }),
    async consumeOnce({ event, applyEffect }) {
      if (processedEventIds.has(event.eventId)) return false;
      await applyEffect({ event });
      processedEventIds.add(event.eventId);
      return true;
    },
  });

  return Object.freeze({
    consumer,
    applyVerifiedEffect,
    snapshot() {
      return {
        processedEventIds: [...processedEventIds].sort(),
        staged: Array.from(stagedBySubject, ([subjectScope, evidence]) => ({
          subjectScope,
          evidenceTypes: [...evidence.keys()].sort(),
        })).sort((left, right) => left.subjectScope.localeCompare(right.subjectScope)),
        securityState: Array.from(securityState, ([subjectScope, state]) => ({
          subjectScope,
          revision: state.revision,
          evidenceTypes: [...state.evidenceTypes],
          evidenceEventIds: [...state.evidenceEventIds],
        })).sort((left, right) => left.subjectScope.localeCompare(right.subjectScope)),
      };
    },
  });
}

function createPipeline({ enrollments, clock, safeguards, revokedSourceIds = new Set() }) {
  const replayGuard = createInMemoryEvidenceReplayGuard({ clock, safeguards });
  const protector = createEvidenceProtector({
    masterKeyBase64Url: EVIDENCE_MASTER_KEY,
    encryptionKeyId: "e2e-evidence-key-v1",
  });
  const ingestion = createEvidenceIngestionService({
    protectEvidence: protector.protect,
    applyReplayGuard: replayGuard,
    async resolveVerificationContext(binding) {
      const enrollment = enrollments.find((candidate) => (
        candidate.tenantId === binding.tenantId
        && candidate.sourceId === binding.sourceId
        && candidate.keyId === binding.keyId
      ));
      if (!enrollment || revokedSourceIds.has(binding.sourceId)) return null;
      return {
        tenantId: binding.tenantId,
        subjectId: binding.subjectId,
        sourceId: enrollment.sourceId,
        evidenceType: enrollment.evidenceType,
        sourceSynthetic: enrollment.synthetic,
        maximumAgeSeconds: maximumAgeFor(enrollment.sourceId),
        sourceState: "active",
        verificationAlgorithm: enrollment.algorithm,
        keyId: enrollment.keyId,
        keyState: "active",
        keyVersion: 1,
        publicKeyBase64Url: enrollment.publicKeyBase64Url,
        publicKeySha256: enrollment.publicKeySha256,
        keyEnrolledAt: "2026-01-01T00:00:00.000Z",
      };
    },
  });
  const stream = createMemoryStream();
  const confirmations = [];
  const publisher = createEvidenceAcceptedPublisher({
    producer: EVENT_PRODUCER,
    keyId: EVENT_SIGNING_KEY_ID,
    sign: (content) => ed25519Sign(null, content, eventPrivateKey),
    validateEvent: validateEvidenceEvent,
    publish: (message) => stream.publish(message),
    async markPublished(mark) {
      confirmations.push(Object.freeze({ ...mark }));
      return {
        eventId: mark.eventId,
        status: "published",
        streamSequence: mark.streamSequence,
        signedEventSha256: mark.signedEventSha256,
      };
    },
    async markFailed(failure) {
      assert.fail(`E2E publication failed: ${failure.failureCode}`);
    },
  });
  const security = createSecurityStateConsumer();

  async function consumePublication(publication) {
    return security.consumer.consume({
      event: publication.event,
      streamSequence: publication.acknowledgement.sequence,
      expectedTenantId: publication.event.tenantId,
      resolvePublicKey: ({ tenantId, keyId }) => (
        tenantId === publication.event.tenantId && keyId === EVENT_SIGNING_KEY_ID
          ? eventPublicKey
          : null
      ),
      applyEffect: security.applyVerifiedEffect,
    });
  }

  return Object.freeze({
    confirmations,
    ingestion,
    publisher,
    replayGuard,
    security,
    stream,
    async acceptPublishAndConsume(envelope) {
      const receipt = await ingestion.ingest({ envelope });
      const claim = outboxClaim(receipt, envelope, clock().toISOString());
      const publication = await publisher.publishClaim({
        context: contextFor(receipt.tenantId, receipt.subjectId),
        claim,
      });
      const consumption = await consumePublication(publication);
      return { receipt, claim, publication, consumption };
    },
    consumePublication,
  });
}

async function rejectedReason(pipeline, envelope) {
  try {
    await pipeline.acceptPublishAndConsume(envelope);
    return null;
  } catch (error) {
    assert.ok(error instanceof EvidenceRejectedError);
    return error.reasonCode;
  }
}

test("accepted evidence crosses ingestion, signed delivery and the test consumer exactly once", async () => {
  const fixture = generateDeterministicDemoEvidenceSet();
  const pipeline = createPipeline({
    enrollments: fixture.enrollments,
    clock: () => new Date("2026-10-05T08:00:30.000Z"),
  });
  const deliveries = [];

  for (const envelope of fixture.envelopes) {
    const delivery = await pipeline.acceptPublishAndConsume(envelope);
    assert.equal(delivery.receipt.status, "accepted");
    assert.equal(delivery.publication.acknowledgement.duplicate, false);
    assert.equal(delivery.consumption.applied, true);
    deliveries.push(delivery);
  }

  assert.equal(pipeline.stream.size, REQUIRED_EVIDENCE_TYPES.length);
  assert.equal(pipeline.confirmations.length, REQUIRED_EVIDENCE_TYPES.length);
  assert.deepEqual(pipeline.security.snapshot().securityState, [{
    subjectScope: `${fixture.tenantId}:${fixture.subjectId}`,
    revision: 1,
    evidenceTypes: [...REQUIRED_EVIDENCE_TYPES],
    evidenceEventIds: deliveries.map(({ publication }) => publication.event.eventId),
  }]);

  const last = deliveries.at(-1);
  const duplicatePublication = await pipeline.publisher.publishClaim({
    context: contextFor(fixture.tenantId, fixture.subjectId),
    claim: last.claim,
  });
  assert.equal(duplicatePublication.acknowledgement.duplicate, true);
  assert.equal(
    duplicatePublication.acknowledgement.sequence,
    last.publication.acknowledgement.sequence,
  );
  const stateBeforeRedelivery = pipeline.security.snapshot();
  const redelivery = await pipeline.consumePublication(duplicatePublication);
  assert.equal(redelivery.applied, false);
  assert.deepEqual(pipeline.security.snapshot(), stateBeforeRedelivery);
});

test("adversarial evidence cannot commit downstream security state", async () => {
  const fixture = generateAdversarialEvidenceFixtureSet({
    observedAt: "2026-10-06T08:00:00.000Z",
  });
  const scenario = (id) => fixture.scenarios.find((candidate) => candidate.id === id);
  const pipelineFor = (selected) => createPipeline({
    enrollments: selected.enrollments,
    clock: () => new Date("2026-10-06T08:00:01.000Z"),
    safeguards: selected.safeguards,
    revokedSourceIds: selected.id === "revoked-source"
      ? new Set(selected.enrollments.map(({ sourceId }) => sourceId))
      : new Set(),
  });

  for (const id of ["forged-signature", "revoked-source", "mixed-tenants"]) {
    const selected = scenario(id);
    const pipeline = pipelineFor(selected);
    assert.equal(
      await rejectedReason(pipeline, selected.envelopes[0]),
      selected.expectedOutcome.reasonCode,
    );
    assert.equal(pipeline.stream.size, 0);
    assert.deepEqual(pipeline.security.snapshot().securityState, []);
  }

  const missing = scenario("missing-signals");
  const missingPipeline = pipelineFor(missing);
  for (const envelope of missing.envelopes) {
    assert.equal((await missingPipeline.acceptPublishAndConsume(envelope)).consumption.applied, true);
  }
  assert.deepEqual(
    missingPipeline.security.snapshot().staged[0].evidenceTypes,
    ["certificate", "device", "identity"],
  );
  assert.deepEqual(missingPipeline.security.snapshot().securityState, []);

  const duplicate = scenario("duplicate-event-id");
  const duplicatePipeline = pipelineFor(duplicate);
  assert.equal(
    (await duplicatePipeline.acceptPublishAndConsume(duplicate.envelopes[0])).consumption.applied,
    true,
  );
  assert.equal(
    await rejectedReason(duplicatePipeline, duplicate.envelopes[1]),
    duplicate.expectedOutcomes[1].reasonCode,
  );
  assert.equal(duplicatePipeline.stream.size, 1);
  assert.deepEqual(duplicatePipeline.security.snapshot().securityState, []);

  const flood = scenario("event-flood");
  const floodPipeline = pipelineFor(flood);
  const outcomes = [];
  for (const envelope of flood.envelopes) {
    outcomes.push((await rejectedReason(floodPipeline, envelope)) ?? "ACCEPTED");
  }
  assert.deepEqual(outcomes, [
    "ACCEPTED",
    "ACCEPTED",
    "ACCEPTED",
    "ACCEPTED",
    "EVIDENCE_RATE_LIMITED",
    "EVIDENCE_RATE_LIMITED",
    "VERIFICATION_CONTEXT_NOT_FOUND",
  ]);
  assert.equal(floodPipeline.stream.size, flood.expectedSummary.acceptedCount);
  assert.deepEqual(floodPipeline.security.snapshot().securityState, []);
});

test("tampered accepted-event delivery is rejected before any consumer effect", async () => {
  const fixture = generateDeterministicDemoEvidenceSet();
  const pipeline = createPipeline({
    enrollments: fixture.enrollments,
    clock: () => new Date("2026-10-05T08:00:30.000Z"),
  });
  const deliveries = [];
  for (const envelope of fixture.envelopes) {
    deliveries.push(await pipeline.acceptPublishAndConsume(envelope));
  }
  const before = pipeline.security.snapshot();
  const original = deliveries.at(-1).publication;
  const tampered = structuredClone(original.event);
  tampered.payload.contentHashSha256 = "0".repeat(64);

  await assert.rejects(
    pipeline.security.consumer.consume({
      event: tampered,
      streamSequence: original.acknowledgement.sequence,
      expectedTenantId: fixture.tenantId,
      resolvePublicKey: () => eventPublicKey,
      applyEffect: pipeline.security.applyVerifiedEffect,
    }),
    (error) => error instanceof EvidenceEventError && error.reasonCode === "SOURCE_SIGNATURE_INVALID",
  );
  assert.deepEqual(pipeline.security.snapshot(), before);
});
