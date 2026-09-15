import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign as ed25519Sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { jetstream, jetstreamManager } from "@nats-io/jetstream";
import { connect } from "@nats-io/transport-node";
import {
  CertificateEventError,
  createCertificateLifecyclePublisher,
  verifyCertificateLifecycleEvent,
} from "@tenant-trust/certificate-events";
import { durableConsumerConfig, EVENT_STREAM, eventStreamConfig } from "@tenant-trust/messaging";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const schemaRoot = resolve(repositoryRoot, "packages/contracts/schemas");
const common = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const certificateSchema = JSON.parse(readFileSync(resolve(schemaRoot, "events/certificate-event.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateEvent = ajv.compile(certificateSchema);

const tenantId = `tnt_${randomUUID()}`;
const subjectId = `sub_${randomUUID()}`;
const issuerId = `iss_${randomUUID()}`;
const correlationOne = `cor_${randomUUID()}`;
const correlationTwo = `cor_${randomUUID()}`;
const certificateOne = `crt_${randomUUID()}`;
const certificateTwo = `crt_${randomUUID()}`;
const certificateThree = `crt_${randomUUID()}`;
const eventIds = Array.from({ length: 5 }, () => `evt_${randomUUID()}`);
const now = Date.now();
const iso = (offset) => new Date(now + offset).toISOString();
const base = {
  tenantId,
  subjectId,
  issuerId,
  serialNumber: "10AF".padEnd(32, "0"),
  fingerprintSha256: "ab".repeat(32),
  requestId: `req_${randomUUID()}`,
  actorSubjectId: subjectId,
  issuerConfirmationId: null,
  reasonCode: null,
};
const records = [
  {
    ...base, eventId: eventIds[0], eventType: "issued", state: "active",
    certificateId: certificateOne, correlationId: correlationOne, causationId: null,
    idempotencyKey: `event-verifier:issued:${randomUUID()}`, notBefore: iso(-60_000),
    notAfter: iso(3_600_000), supersedesCertificateId: null,
    occurredAt: iso(-5_000), recordedAt: iso(-4_000),
  },
  {
    ...base, eventId: eventIds[1], eventType: "renewed", state: "active",
    certificateId: certificateTwo, serialNumber: "20AF".padEnd(32, "0"), fingerprintSha256: "bc".repeat(32),
    correlationId: correlationOne, causationId: eventIds[0],
    idempotencyKey: `event-verifier:renewed:${randomUUID()}`, notBefore: iso(-3_000),
    notAfter: iso(7_200_000), supersedesCertificateId: certificateOne,
    occurredAt: iso(-3_000), recordedAt: iso(-2_500),
  },
  {
    ...base, eventId: eventIds[2], eventType: "revoked", state: "revoked",
    certificateId: certificateTwo, serialNumber: "20AF".padEnd(32, "0"), fingerprintSha256: "bc".repeat(32),
    correlationId: correlationOne, causationId: eventIds[1],
    idempotencyKey: `event-verifier:revoked:${randomUUID()}`, reasonCode: "KEY_COMPROMISE",
    issuerConfirmationId: `step-ca:revocation:${randomUUID()}`,
    occurredAt: iso(-2_000), recordedAt: iso(-1_500),
  },
  {
    ...base, eventId: eventIds[3], eventType: "issued", state: "active",
    certificateId: certificateThree, serialNumber: "30AF".padEnd(32, "0"), fingerprintSha256: "cd".repeat(32),
    correlationId: correlationTwo, causationId: null,
    idempotencyKey: `event-verifier:issued-expiry:${randomUUID()}`, notBefore: iso(-7_200_000),
    notAfter: iso(-2_000), supersedesCertificateId: null,
    occurredAt: iso(-7_000), recordedAt: iso(-6_500),
  },
  {
    ...base, eventId: eventIds[4], eventType: "expired", state: "expired",
    certificateId: certificateThree, serialNumber: "30AF".padEnd(32, "0"), fingerprintSha256: "cd".repeat(32),
    correlationId: correlationTwo, causationId: eventIds[3], actorSubjectId: null,
    idempotencyKey: `event-verifier:expired:${randomUUID()}`, notAfter: iso(-2_000),
    reasonCode: "CERTIFICATE_EXPIRED", occurredAt: iso(-1_000), recordedAt: iso(-500),
  },
];

const context = resolveTenantContext({
  authentication: { source: "trusted-session", authenticationId: `certificate-event-verifier:${randomUUID()}`, tenantId, subjectId },
  authority: {
    tenant: { tenantId, state: "active", version: 1 },
    subject: { subjectId, state: "active", version: 1 },
    membership: { tenantId, subjectId, state: "active", version: 1 },
    roles: ["tenant-member"],
  },
});
const producer = { service: "certificate-events", instanceId: "local-verifier" };
const keyId = `certificate-events:key-${randomUUID()}`;
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const connection = await connect({
  servers: `nats://127.0.0.1:${environment.NATS_HOST_PORT}`,
  user: environment.NATS_USER,
  pass: environment.NATS_PASSWORD,
  name: "tenant-trust-certificate-event-verifier",
  timeout: 5_000,
});

try {
  const manager = await jetstreamManager(connection);
  const client = jetstream(connection);
  const streamNames = await manager.streams.names().next();
  if (streamNames.includes(EVENT_STREAM)) await manager.streams.update(EVENT_STREAM, eventStreamConfig());
  else await manager.streams.add(eventStreamConfig());

  const durableMarks = [];
  const publisher = createCertificateLifecyclePublisher({
    producer,
    keyId,
    sign: (content) => ed25519Sign(null, content, privateKey),
    validateEvent,
    async publish({ subject, payload, messageId }) {
      const acknowledgement = await client.publish(subject, payload, { msgID: messageId });
      return { stream: acknowledgement.stream, sequence: acknowledgement.seq, duplicate: acknowledgement.duplicate };
    },
    async markPublished(mark) {
      durableMarks.push(mark);
      return { eventId: mark.eventId, status: "published", streamSequence: mark.streamSequence, signedEventSha256: mark.signedEventSha256 };
    },
    async markFailed(failure) {
      assert.fail(`live publication failed: ${failure.failureCode}`);
    },
  });

  const published = [];
  for (const [index, record] of records.entries()) {
    published.push(await publisher.publishClaim({
      context,
      claim: { ...record, claimToken: `clm_${randomUUID()}`, attemptCount: 1 },
    }));
    assert.equal(durableMarks[index].eventId, record.eventId);
  }

  const durableName = `certificate_events_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
  await manager.consumers.add(EVENT_STREAM, durableConsumerConfig(context, {
    durableName,
    eventFilter: "certificate.>",
    startSequence: published[0].acknowledgement.sequence,
    backoff: [250_000_000, 500_000_000, 1_000_000_000],
  }));
  const consumer = await client.consumers.get(EVENT_STREAM, durableName);
  const received = [];
  for (let index = 0; index < records.length; index++) {
    const message = await consumer.next({ expires: 5_000 });
    assert.ok(message, `missing certificate lifecycle event ${index + 1}`);
    const event = message.json();
    await verifyCertificateLifecycleEvent({
      event,
      validateEvent,
      expectedTenantId: tenantId,
      resolvePublicKey(binding) {
        assert.equal(binding.keyId, keyId);
        assert.equal(binding.producer.service, producer.service);
        return publicKey;
      },
    });
    received.push(event);
    assert.equal(await message.ackAck({ timeout: 3_000 }), true);
  }
  assert.deepEqual(received.map((event) => event.eventType), [
    "certificate.issued.v1",
    "certificate.renewed.v1",
    "certificate.revoked.v1",
    "certificate.issued.v1",
    "certificate.expired.v1",
  ]);
  assert.equal(received[1].causationId, received[0].eventId);
  assert.equal(received[2].causationId, received[1].eventId);
  assert.equal(received[4].causationId, received[3].eventId);

  const tampered = structuredClone(received[2]);
  tampered.payload.reasonCode = "CA_COMPROMISE";
  await assert.rejects(
    verifyCertificateLifecycleEvent({ event: tampered, resolvePublicKey: () => publicKey }),
    (error) => error instanceof CertificateEventError && error.reasonCode === "SOURCE_SIGNATURE_INVALID",
  );
  await manager.consumers.delete(EVENT_STREAM, durableName);

  console.log("PASS issued, renewed, revoked and expired certificate events received acknowledged JetStream publication");
  console.log("PASS every received event validated its Ed25519 source signature and tenant-bound key lookup");
  console.log("PASS renewal, revocation and expiry preserved their immediate causal event IDs");
  console.log("PASS tampered signed lifecycle content was rejected before consumer processing");
} finally {
  await connection.drain();
}
