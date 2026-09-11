# Messaging

This package owns the NATS JetStream stream and consumer defaults shared by event producers and consumers. `subjectForEvent` requires a resolved tenant context, verifies that the event envelope agrees with it and derives the subject from that trusted tenant plus the complete versioned event type.

`eventStreamConfig` keeps validated events in a bounded file-backed stream. `durableConsumerConfig` also requires the resolved context and constructs an exact tenant prefix around a validated event filter. It uses explicit acknowledgement, bounded exponential backoff and one in-flight message per consumer so retries cannot overtake an event for that consumer.

The local broker adds exact Tenant Alpha and Tenant Beta publish/subscribe permissions. Consumers still enforce schema, idempotency and envelope-to-state checks because JetStream provides at-least-once delivery and privileged service accounts can span tenants. Send an acknowledgement only after the consumer's durable effect and event receipt are committed.
