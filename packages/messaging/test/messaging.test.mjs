import assert from "node:assert/strict";
import { test } from "node:test";
import {
  EVENT_STREAM,
  durableConsumerConfig,
  eventStreamConfig,
  subjectForEvent,
} from "../src/index.mjs";

const event = {
  tenantId: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  eventType: "trust.updated.v1",
};

test("event subjects preserve tenant scope and the versioned event type", () => {
  assert.equal(
    subjectForEvent(event),
    "tenant.tnt_018f1234-5678-7abc-8def-0123456789ab.events.trust.updated.v1",
  );
  assert.throws(() => subjectForEvent({ ...event, tenantId: "*" }), /tenantId/u);
  assert.throws(() => subjectForEvent({ ...event, eventType: "trust updated" }), /eventType/u);
});

test("the stream is file-backed, bounded and configured for publisher deduplication", () => {
  const config = eventStreamConfig();
  assert.equal(config.name, EVENT_STREAM);
  assert.equal(config.storage, "file");
  assert.equal(config.retention, "limits");
  assert.equal(config.max_age, 604_800_000_000_000);
  assert.equal(config.max_bytes, 536_870_912);
  assert.equal(config.duplicate_window, 120_000_000_000);
});

test("durable consumers require explicit acknowledgements and bounded retry", () => {
  const config = durableConsumerConfig({
    durableName: "trust_worker_v1",
    filterSubject: "tenant.*.events.trust.>",
    startSequence: 42,
  });
  assert.equal(config.ack_policy, "explicit");
  assert.equal(config.deliver_policy, "by_start_sequence");
  assert.equal(config.opt_start_seq, 42);
  assert.equal(config.max_deliver, 5);
  assert.deepEqual(config.backoff, [1, 5, 30, 120, 600].map((seconds) => seconds * 1_000_000_000));
  assert.equal(config.max_ack_pending, 1);
});
