# Messaging

This package owns the NATS JetStream stream and consumer defaults shared by event producers and consumers. `subjectForEvent` derives the subject from a validated event, preserving tenant scope and the complete versioned event type.

`eventStreamConfig` keeps validated events in a bounded file-backed stream. `durableConsumerConfig` uses explicit acknowledgement, bounded exponential backoff and one in-flight message per consumer so retries cannot overtake an event for that consumer.

Consumers still enforce the idempotency and tenant checks in the contracts package. JetStream provides at-least-once delivery, so an acknowledgement is sent only after the consumer's durable effect and event receipt are committed.
