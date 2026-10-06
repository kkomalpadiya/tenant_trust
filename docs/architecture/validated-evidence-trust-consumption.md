# Concurrency-safe validated evidence consumption

T6.5 joins the durable accepted-evidence event boundary from T5.8 to the versioned trust-state boundary from T6.2. The consumer accepts only an `evidence.accepted.v1` event that has passed the producer signature, schema and expected-tenant checks. It does not trust caller-selected tenant, subject, evidence type, observation time or evidence identity.

## Normalization boundary

Accepted events contain metadata, not the raw evidence payload. `createValidatedEvidenceTrustConsumer` therefore requires a trusted `resolveComponentScore` callback. A deployed worker uses the verified tenant, subject and source-event binding to retrieve and authenticate the encrypted accepted envelope, then applies the appropriate evidence-type normalizer. The callback returns one finite component value on the T6.1 inclusive 0–100 scale.

Signature verification completes before the callback runs. A verification failure cannot retrieve evidence, calculate a component or reach PostgreSQL. T6.5 defines the safe consumption and persistence contract; evidence-type-specific raw-claim normalization remains a separate implementation concern.

## Atomic effect and state update

Migration `021_validated_evidence_trust_consumption.sql` adds `trust.subject_component_observations` and the execute-only `trust.consume_validated_evidence_component` function. One function call performs the following work in the caller's transaction:

1. bind the delivery event, evidence ID, stream sequence and signed-event digest to one published outbox row;
2. load the authoritative tenant, subject, evidence type, source identity, source sequence and timestamps from the accepted receipt;
3. acquire a transaction-scoped advisory lock derived from the tenant and subject;
4. record the existing durable `(consumer, tenant, event)` effect receipt;
5. stage the observation only when its ordering tuple is newer than the stored component tuple; and
6. once all five components exist, append a complete T6.2 state version and advance its current pointer.

The ordering tuple is observation time, JetStream sequence and delivery event ID. An older delivery is durably acknowledged as `superseded` but cannot replace a newer component or create a rollback version. Incomplete sets return `staged`; they never create a partial state or turn missing evidence into zero.

The subject lock serializes workers that race on different components of the same tenant-and-subject aggregate. Each worker reads the state produced by the preceding transaction before it appends the next version, so optimistic versions cannot be lost or silently overwritten. Different subjects do not share that lock except for the negligible possibility of an advisory-hash collision, which would cause safe extra serialization rather than incorrect state.

## Idempotency and isolation

The effect receipt and component/state changes commit together. Redelivery returns `duplicate` and performs no second stage or state write. A failed normalization, invalid database result or transaction error rolls back without retaining an effect receipt, so the same event remains retryable.

The runtime role has execute permission only on the constrained function and no direct access to staging, outbox, receipt or trust-state tables. The function derives every scope field from the exact published row, validates all five evidence references again through T6.2 and rejects a delivery event presented under another tenant.

Run `npm run trust-evidence-consumer:verify` after migrations. The gate runs the trust-service tests and a rolled-back PostgreSQL scenario for staging, complete snapshots, duplicate delivery, reordered evidence, successive subject updates, role restrictions and tenant substitution.
