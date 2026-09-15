# Signed certificate lifecycle events

`@tenant-trust/certificate-events` converts an authoritative certificate lifecycle outbox row into the versioned certificate event contract, signs the canonical unsigned envelope with Ed25519, publishes it to the tenant-scoped JetStream subject with `eventId` as the NATS message ID, and marks the outbox row published only after the server acknowledgement is durable.

The signature covers every unsigned envelope and payload field using `tenant-trust-json-v1`, which recursively sorts object keys and preserves array order. `signedContentSha256` allows consumers to compare the exact signed bytes before resolving the tenant-, producer- and key-bound public key. A signature authenticates the configured producer; it does not prove the event is truthful. Consumers must still validate the contract, tenant and aggregate bindings, causal prerequisites, freshness where relevant and idempotency before applying an effect.

Private signing keys stay outside Git and PostgreSQL. The package accepts an asynchronous signing callback so production code can use an external keystore or HSM. The local verifier generates a disposable Ed25519 key pair in memory and retains neither key after the process exits.

Migration 011 adds a transactional outbox row for every certificate lifecycle record, including pre-existing records, plus constrained claim, success and retry functions for the `tenant_trust_certificate_event_worker` role. Claims recover after five minutes, publish failures return to pending with bounded exponential delay, and successful rows retain only the signed-event digest and JetStream sequence. At-least-once retries can republish after the broker deduplication window, so consumers must keep durable `(consumer, eventId)` idempotency.
