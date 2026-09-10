# Reliable event delivery

Tenant Trust uses NATS JetStream for asynchronous security domain events. JetStream stores validated events in the file-backed `TENANT_TRUST_EVENTS` stream and provides at-least-once delivery. PostgreSQL remains the source of truth for application state, and later audit work commits selected event hashes to Hyperledger Fabric asynchronously.

## Subjects and tenant scope

Publish a contract-valid event to `tenant.<tenantId>.events.<eventType>`. For example, a trust transition uses `tenant.tnt_...events.trust.updated.v1`. Producers derive this subject from the validated envelope. Consumers subscribe to the narrowest tenant and event filter their responsibility allows and verify the envelope tenant against trusted aggregate state before applying an effect.

The local stream retains up to 512 MiB for seven days and discards the oldest messages when a limit is reached. It uses file storage in the `tenant-trust-nats-data` Docker volume. These limits support development and evaluation and must be reviewed before any non-local deployment.

## Publishing and deduplication

Use a JetStream publish and wait for its server acknowledgement. Set the NATS message ID to the contract `eventId`. The stream rejects a repeat message ID during its two-minute duplicate window. This handles immediate publisher retries, while durable application constraints still enforce event and idempotency uniqueness beyond that window.

Do not publish an event before its originating state change and outbox record commit. A later application task will implement the transactional outbox. A plain Core NATS publish does not provide the required persistence acknowledgement.

## Consumption and retry

Use named durable pull consumers with explicit acknowledgement. Apply these rules:

1. Validate the schema, tenant scope, event identity and causal prerequisites.
2. Record `(consumerName, eventId)` and apply the effect in one PostgreSQL transaction where possible.
3. Send a confirmed acknowledgement only after that transaction commits.
4. Acknowledge an identical duplicate without repeating the effect. Reject and audit conflicting content for the same identity.
5. Negatively acknowledge a transient failure. The standard retry delays are 1 second, 5 seconds, 30 seconds, 2 minutes and 10 minutes, with at most five deliveries.
6. After the final attempt, retain the event in the stream and surface the failure through reconciliation and an auditable failure event. Never silently discard a security event.

Each default consumer allows one unacknowledged message at a time. This preserves processing order within that consumer while the prototype is small. Scale later with partitioned consumers only after aggregate ordering and idempotency tests exist.

## Replay

Create a separate durable consumer with an explicit start sequence or start time. Replay uses the same validation, tenant and idempotency checks as live delivery. An acknowledged message remains replayable because the stream uses limits retention rather than work-queue retention.

Run `npm run messaging:verify` against the local stack. The verifier validates a synthetic event, publishes it with a message ID, proves duplicate suppression, negatively acknowledges the first delivery, confirms redelivery, acknowledges it and replays the same stored sequence through a second durable consumer.
