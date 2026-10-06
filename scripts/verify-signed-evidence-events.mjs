import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign as ed25519Sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { jetstream, jetstreamManager } from "@nats-io/jetstream";
import { connect } from "@nats-io/transport-node";
import {
  createEvidenceAcceptedConsumer,
  createEvidenceAcceptedPublisher,
  verifyEvidenceAcceptedEvent,
} from "@tenant-trust/evidence-events";
import { durableConsumerConfig, EVENT_STREAM, eventStreamConfig } from "@tenant-trust/messaging";
import { resolveTenantContext } from "@tenant-trust/tenant-context";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

const schemaRoot = resolve(repositoryRoot, "packages/contracts/schemas");
const common = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const evidenceSchema = JSON.parse(readFileSync(resolve(schemaRoot, "events/evidence-event.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(common);
const validateEvent = ajv.compile(evidenceSchema);

const tenantId = `tnt_${randomUUID()}`;
const subjectId = `sub_${randomUUID()}`;
const sourceId = `src_${randomUUID()}`;
const evidenceId = `evd_${randomUUID()}`;
const eventId = `evt_${randomUUID()}`;
const sourceEventId = `evt_${randomUUID()}`;
const correlationId = `cor_${randomUUID()}`;
const claimToken = `clm_${randomUUID()}`;
const acceptedAt = new Date();
const record = {
  tenantId,
  subjectId,
  sourceId,
  evidenceId,
  eventId,
  sourceEventId,
  correlationId,
  evidenceType: "device",
  sourceSequence: 17,
  contentHashSha256: "ab".repeat(32),
  synthetic: true,
  observedAt: new Date(acceptedAt.getTime() - 1_000).toISOString(),
  acceptedAt: acceptedAt.toISOString(),
  expiresAt: new Date(acceptedAt.getTime() + 300_000).toISOString(),
  claimToken,
  attemptCount: 1,
};
const context = resolveTenantContext({
  authentication: { source: "trusted-session", authenticationId: `evidence-event-verifier:${randomUUID()}`, tenantId, subjectId },
  authority: {
    tenant: { tenantId, state: "active", version: 1 },
    subject: { subjectId, state: "active", version: 1 },
    membership: { tenantId, subjectId, state: "active", version: 1 },
    roles: ["tenant-member"],
  },
});
const producer = { service: "evidence-events", instanceId: "local-verifier" };
const keyId = `evidence-events:key-${randomUUID()}`;
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const connection = await connect({
  servers: `nats://127.0.0.1:${environment.NATS_HOST_PORT}`,
  user: environment.NATS_USER,
  pass: environment.NATS_PASSWORD,
  name: "tenant-trust-evidence-event-verifier",
  timeout: 5_000,
});

try {
  const manager = await jetstreamManager(connection);
  const client = jetstream(connection);
  const streamNames = await manager.streams.names().next();
  if (streamNames.includes(EVENT_STREAM)) await manager.streams.update(EVENT_STREAM, eventStreamConfig());
  else await manager.streams.add(eventStreamConfig());

  const confirmations = [];
  const publisher = createEvidenceAcceptedPublisher({
    producer,
    keyId,
    sign: (content) => ed25519Sign(null, content, privateKey),
    validateEvent,
    async publish({ subject, payload, messageId }) {
      const acknowledgement = await client.publish(subject, payload, { msgID: messageId });
      return { stream: acknowledgement.stream, sequence: acknowledgement.seq, duplicate: acknowledgement.duplicate };
    },
    async markPublished(mark) {
      confirmations.push(mark);
      return { eventId: mark.eventId, status: "published", streamSequence: mark.streamSequence, signedEventSha256: mark.signedEventSha256 };
    },
    async markFailed(failure) {
      assert.fail(`live evidence publication failed: ${failure.failureCode}`);
    },
  });
  const published = await publisher.publishClaim({ context, claim: record });
  assert.equal(confirmations.length, 1);
  const duplicate = await client.publish(
    published.subject,
    Buffer.from(JSON.stringify(published.event), "utf8"),
    { msgID: published.event.eventId },
  );
  assert.equal(duplicate.seq, published.acknowledgement.sequence);
  assert.equal(duplicate.duplicate, true);

  const durableName = `evidence_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
  await manager.consumers.add(EVENT_STREAM, durableConsumerConfig(context, {
    durableName,
    eventFilter: "evidence.accepted.v1",
    startSequence: published.acknowledgement.sequence,
    backoff: [250_000_000, 500_000_000, 1_000_000_000],
  }));

  const durableEffects = new Set();
  let effectCount = 0;
  const createConsumerProcess = () => createEvidenceAcceptedConsumer({
    consumerName: "trust-engine.v1",
    verifyEvent: (options) => verifyEvidenceAcceptedEvent({ ...options, validateEvent }),
    async consumeOnce({ event, applyEffect }) {
      if (durableEffects.has(event.eventId)) return false;
      await applyEffect({ event });
      durableEffects.add(event.eventId);
      return true;
    },
  });

  const firstConsumer = await client.consumers.get(EVENT_STREAM, durableName);
  const first = await firstConsumer.next({ expires: 5_000 });
  assert.ok(first, "The durable consumer did not receive the accepted-evidence event.");
  const firstResult = await createConsumerProcess().consume({
    event: first.json(),
    streamSequence: first.seq,
    expectedTenantId: tenantId,
    resolvePublicKey: () => publicKey,
    applyEffect: async () => { effectCount += 1; },
  });
  assert.equal(firstResult.applied, true);
  first.nak(250);

  const restartedConsumer = await client.consumers.get(EVENT_STREAM, durableName);
  const redelivery = await restartedConsumer.next({ expires: 5_000 });
  assert.ok(redelivery, "The unacknowledged event was not redelivered after consumer restart.");
  assert.equal(redelivery.info.deliveryCount, 2);
  const retryResult = await createConsumerProcess().consume({
    event: redelivery.json(),
    streamSequence: redelivery.seq,
    expectedTenantId: tenantId,
    resolvePublicKey: () => publicKey,
    applyEffect: async () => { effectCount += 1; },
  });
  assert.equal(retryResult.applied, false);
  assert.equal(effectCount, 1);
  assert.equal(await redelivery.ackAck({ timeout: 3_000 }), true);

  const info = await manager.consumers.info(EVENT_STREAM, durableName);
  assert.equal(info.num_ack_pending, 0);
  await manager.consumers.delete(EVENT_STREAM, durableName);

  console.log("PASS signed evidence.accepted.v1 metadata reached the tenant-scoped file-backed stream");
  console.log("PASS duplicate publish reused the stable event ID and JetStream sequence");
  console.log("PASS consumer restart redelivered the unacknowledged event without repeating its effect");
  console.log("PASS acknowledgement occurred only after verified durable consume-once processing");
} finally {
  await connection.drain();
}
