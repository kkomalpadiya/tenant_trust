# Accepted evidence events

This package turns an authoritative accepted-evidence outbox claim into a signed `evidence.accepted.v1` event. The event contains identifiers, timestamps, type, sequence and the accepted content digest; it never contains raw evidence or ciphertext.

The publisher signs deterministic JSON, publishes with the delivery event ID as the JetStream message ID, waits for the stream acknowledgement and only then confirms the exact database claim. Failures return the claim to `pending`, and claims abandoned for five minutes are recoverable after a worker restart.

Consumers verify the contract, tenant and Ed25519 source signature before calling an atomic `consumeOnce` boundary. The PostgreSQL implementation records `(consumer, tenant, event)` in the same transaction as the supplied downstream effect. A redelivery therefore returns `false` and must be acknowledged without applying the effect again.
