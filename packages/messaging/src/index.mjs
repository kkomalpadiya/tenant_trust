import { assertNoTenantSwitch } from "@tenant-trust/tenant-context";

export const EVENT_STREAM = "TENANT_TRUST_EVENTS";
export const EVENT_SUBJECT_PATTERN = "tenant.*.events.>";

const SECOND = 1_000_000_000;
const DEFAULT_BACKOFF = [1 * SECOND, 5 * SECOND, 30 * SECOND, 120 * SECOND, 600 * SECOND];
const SUBJECT_TOKEN = /^[A-Za-z0-9_-]+$/u;
const EVENT_TYPE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+\.v[1-9][0-9]*$/u;
const EVENT_PREFIX_FILTER = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.>$/u;

export function subjectForEvent(context, event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new TypeError("A contract-valid event is required to build an event subject.");
  }
  const trustedContext = assertNoTenantSwitch(context, [
    { source: "body", tenantId: event.tenantId },
  ]);
  if (!EVENT_TYPE.test(event.eventType ?? "")) {
    throw new TypeError("A versioned eventType is required to build an event subject.");
  }
  return `tenant.${trustedContext.tenantId}.events.${event.eventType}`;
}

export function eventStreamConfig() {
  return {
    name: EVENT_STREAM,
    description: "Validated, tenant-scoped security domain events",
    subjects: [EVENT_SUBJECT_PATTERN],
    storage: "file",
    retention: "limits",
    discard: "old",
    max_age: 7 * 24 * 60 * 60 * SECOND,
    max_bytes: 512 * 1024 * 1024,
    duplicate_window: 2 * 60 * SECOND,
    allow_direct: true,
  };
}

export function durableConsumerConfig(context, {
  durableName,
  eventFilter = ">",
  startSequence,
  backoff = DEFAULT_BACKOFF,
} = {}) {
  const trustedContext = assertNoTenantSwitch(context);
  if (!SUBJECT_TOKEN.test(durableName ?? "")) {
    throw new TypeError("durableName must be one NATS-safe token.");
  }
  if (eventFilter !== ">" && !EVENT_TYPE.test(eventFilter ?? "") && !EVENT_PREFIX_FILTER.test(eventFilter ?? "")) {
    throw new TypeError("eventFilter must be a versioned event type, a terminal prefix wildcard, or >.");
  }
  if (!Array.isArray(backoff) || backoff.length === 0 || backoff.some((delay) => !Number.isSafeInteger(delay) || delay <= 0)) {
    throw new TypeError("backoff must contain positive integer nanosecond delays.");
  }

  const config = {
    durable_name: durableName,
    description: "Durable tenant security event processor",
    filter_subject: `tenant.${trustedContext.tenantId}.events.${eventFilter}`,
    ack_policy: "explicit",
    deliver_policy: startSequence === undefined ? "all" : "by_start_sequence",
    replay_policy: "instant",
    max_deliver: backoff.length,
    backoff,
    max_ack_pending: 1,
  };
  if (startSequence !== undefined) config.opt_start_seq = startSequence;
  return config;
}
