import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveTenantContext, TenantContextError } from "@tenant-trust/tenant-context";
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

function contextFor(tenantId, authenticationId) {
  return resolveTenantContext({
    authentication: {
      source: "trusted-session",
      authenticationId,
      tenantId,
      subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
    },
    authority: {
      tenant: { tenantId, state: "active", version: 1 },
      subject: { subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad", state: "active", version: 1 },
      membership: {
        tenantId,
        subjectId: "sub_018f1234-5678-7abc-8def-0123456789ad",
        state: "active",
        version: 1,
      },
      roles: ["tenant-member"],
    },
  });
}

const alphaContext = contextFor(event.tenantId, "session-alpha");
const betaContext = contextFor("tnt_018f1234-5678-7abc-8def-0123456789ac", "session-beta");

test("event subjects preserve tenant scope and the versioned event type", () => {
  assert.equal(
    subjectForEvent(alphaContext, event),
    "tenant.tnt_018f1234-5678-7abc-8def-0123456789ab.events.trust.updated.v1",
  );
  assert.throws(
    () => subjectForEvent(betaContext, event),
    (error) => error instanceof TenantContextError && error.reasonCode === "TENANT_CONTEXT_MISMATCH",
  );
  assert.throws(() => subjectForEvent(alphaContext, { ...event, eventType: "trust updated" }), /eventType/u);
  assert.throws(
    () => subjectForEvent({ tenantId: event.tenantId }, event),
    (error) => error instanceof TenantContextError && error.reasonCode === "TENANT_CONTEXT_INVALID",
  );
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
  const config = durableConsumerConfig(alphaContext, {
    durableName: "trust_worker_v1",
    eventFilter: "trust.>",
    startSequence: 42,
  });
  assert.equal(config.ack_policy, "explicit");
  assert.equal(config.deliver_policy, "by_start_sequence");
  assert.equal(config.opt_start_seq, 42);
  assert.equal(config.max_deliver, 5);
  assert.deepEqual(config.backoff, [1, 5, 30, 120, 600].map((seconds) => seconds * 1_000_000_000));
  assert.equal(config.max_ack_pending, 1);
  assert.equal(
    config.filter_subject,
    "tenant.tnt_018f1234-5678-7abc-8def-0123456789ab.events.trust.>",
  );
  assert.throws(
    () => durableConsumerConfig(alphaContext, {
      durableName: "unsafe_worker_v1",
      eventFilter: "*.>",
    }),
    /eventFilter/u,
  );
});
