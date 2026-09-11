import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { jetstream, jetstreamManager } from "@nats-io/jetstream";
import { connect } from "@nats-io/transport-node";
import {
  EVENT_STREAM,
  durableConsumerConfig,
  eventStreamConfig,
  subjectForEvent,
} from "@tenant-trust/messaging";
import { environment, repositoryRoot } from "./lib/foundation-context.mjs";

for (const key of ["NATS_HOST_PORT", "NATS_USER", "NATS_PASSWORD"]) {
  if (!environment[key]) throw new Error(`Missing ${key}; run npm run infra:init.`);
}

const schemaRoot = resolve(repositoryRoot, "packages/contracts/schemas");
const commonSchema = JSON.parse(readFileSync(resolve(schemaRoot, "common.schema.json"), "utf8"));
const tenantSchema = JSON.parse(readFileSync(resolve(schemaRoot, "events/tenant-event.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(commonSchema);
const validateTenantEvent = ajv.compile(tenantSchema);

const tenantUuid = randomUUID();
const eventUuid = randomUUID();
const correlationUuid = randomUUID();
const now = new Date().toISOString();
const event = {
  schemaVersion: "1.0.0",
  eventId: `evt_${eventUuid}`,
  eventType: "tenant.created.v1",
  tenantId: `tnt_${tenantUuid}`,
  subjectId: null,
  aggregateId: `tnt_${tenantUuid}`,
  correlationId: `cor_${correlationUuid}`,
  causationId: null,
  idempotencyKey: `delivery-demo:${eventUuid}`,
  occurredAt: now,
  recordedAt: now,
  producer: { service: "delivery-verifier", instanceId: "local" },
  payload: { state: "active", displayName: "Synthetic Delivery Demo Tenant" },
};
assert.equal(validateTenantEvent(event), true, ajv.errorsText(validateTenantEvent.errors));

const connection = await connect({
  servers: `nats://127.0.0.1:${environment.NATS_HOST_PORT}`,
  user: environment.NATS_USER,
  pass: environment.NATS_PASSWORD,
  name: "tenant-trust-delivery-verifier",
  timeout: 5_000,
});

async function resetConsumer(manager, name, config) {
  const consumers = await manager.consumers.list(EVENT_STREAM).next();
  if (consumers.some((consumer) => consumer.name === name)) {
    await manager.consumers.delete(EVENT_STREAM, name);
  }
  await manager.consumers.add(EVENT_STREAM, config);
}

try {
  const manager = await jetstreamManager(connection);
  const client = jetstream(connection);
  const streamNames = await manager.streams.names().next();
  if (streamNames.includes(EVENT_STREAM)) {
    await manager.streams.update(EVENT_STREAM, eventStreamConfig());
  } else {
    await manager.streams.add(eventStreamConfig());
  }

  const subject = subjectForEvent(event);
  const payload = new TextEncoder().encode(JSON.stringify(event));
  const publishAck = await client.publish(subject, payload, { msgID: event.eventId });
  assert.equal(publishAck.stream, EVENT_STREAM);
  assert.equal(publishAck.duplicate, false);

  const duplicateAck = await client.publish(subject, payload, { msgID: event.eventId });
  assert.equal(duplicateAck.seq, publishAck.seq);
  assert.equal(duplicateAck.duplicate, true);

  const shortBackoff = [250_000_000, 500_000_000, 1_000_000_000];
  await resetConsumer(manager, "delivery_demo_v1", durableConsumerConfig({
    durableName: "delivery_demo_v1",
    filterSubject: subject,
    startSequence: publishAck.seq,
    backoff: shortBackoff,
  }));
  const consumer = await client.consumers.get(EVENT_STREAM, "delivery_demo_v1");
  const firstDelivery = await consumer.next({ expires: 5_000 });
  assert.ok(firstDelivery, "The durable consumer did not receive the published event.");
  assert.equal(firstDelivery.seq, publishAck.seq);
  assert.equal(firstDelivery.info.deliveryCount, 1);
  assert.deepEqual(firstDelivery.json(), event);
  firstDelivery.nak(250);

  const retryDelivery = await consumer.next({ expires: 5_000 });
  assert.ok(retryDelivery, "The negatively acknowledged event was not redelivered.");
  assert.equal(retryDelivery.seq, publishAck.seq);
  assert.equal(retryDelivery.redelivered, true);
  assert.equal(retryDelivery.info.deliveryCount, 2);
  assert.equal(await retryDelivery.ackAck({ timeout: 3_000 }), true);

  await resetConsumer(manager, "replay_demo_v1", durableConsumerConfig({
    durableName: "replay_demo_v1",
    filterSubject: subject,
    startSequence: publishAck.seq,
  }));
  const replayConsumer = await client.consumers.get(EVENT_STREAM, "replay_demo_v1");
  const replay = await replayConsumer.next({ expires: 5_000 });
  assert.ok(replay, "The acknowledged event could not be replayed from the stream.");
  assert.equal(replay.seq, publishAck.seq);
  assert.deepEqual(replay.json(), event);
  assert.equal(await replay.ackAck({ timeout: 3_000 }), true);

  const streamInfo = await manager.streams.info(EVENT_STREAM);
  assert.ok(streamInfo.state.messages >= 1);
  assert.equal(streamInfo.config.storage, "file");
  const consumerInfo = await manager.consumers.info(EVENT_STREAM, "delivery_demo_v1");
  assert.equal(consumerInfo.config.ack_policy, "explicit");
  assert.equal(consumerInfo.num_ack_pending, 0);

  console.log(`PASS validated and published ${event.eventType} at stream sequence ${publishAck.seq}`);
  console.log("PASS duplicate eventId was rejected by the stream deduplication window");
  console.log("PASS explicit negative acknowledgement caused delivery attempt 2");
  console.log("PASS confirmed acknowledgement cleared the durable consumer's pending state");
  console.log("PASS a second durable consumer replayed the stored event by sequence");
} finally {
  await connection.drain();
}
