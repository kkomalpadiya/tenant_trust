# Accepted evidence event delivery

Accepted evidence crosses the ingestion boundary through a transactional outbox and a tenant-scoped JetStream subject. The delivery contains only identifiers, bounded metadata and the already accepted content digest. Raw evidence, ciphertext, nonces and encryption material remain out of the stream.

## Atomic acceptance and enqueue

Migration 019 attaches an `AFTER INSERT` trigger to `trust.evidence_ingestion_receipts`. It allocates server-owned evidence, delivery-event and correlation IDs and inserts one pending outbox row in the same transaction. Migration 017's deferred constraint still requires the corresponding encrypted evidence row before commit. If encryption or storage fails, the receipt and outbox row roll back together; an event cannot describe evidence that was not durably accepted and protected.

Existing accepted receipts are backfilled once when the migration is applied. Delivery workers have no direct table privileges and can access only tenant-scoped claim and outcome functions.

## Retry and restart behavior

The worker claims the oldest due event with `FOR UPDATE SKIP LOCKED` and an opaque claim token. A claim left in `publishing` for five minutes is returned to `pending`, allowing a restarted worker to recover it. A failed publish records a bounded reason and retry delay.

The publisher builds `evidence.accepted.v1`, signs canonical JSON with Ed25519, publishes to `tenant.<tenantId>.events.evidence.accepted.v1` using the stable delivery event ID as the NATS message ID, and waits for the JetStream acknowledgement. Only the exact active claim can then be marked published with its stream sequence and signed-event digest.

JetStream is at-least-once. Its duplicate window suppresses immediate publisher retries, while consumers use the durable `(consumer, tenant, event)` ledger for retries outside that window and redelivery after restarts. `record_evidence_event_effect` verifies the event against the acknowledged outbox digest and sequence. A consumer must call it and apply its downstream effect in the same PostgreSQL transaction, then acknowledge the message only after that transaction commits.

## Verification

Run `npm run evidence-events:verify`. The gate validates contracts and signatures, exercises transactional enqueue, publish failure, stale-claim recovery and duplicate-effect suppression in PostgreSQL, and proves duplicate publication plus unacknowledged redelivery through the real local JetStream.
