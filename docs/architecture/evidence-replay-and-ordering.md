# Evidence freshness, replay and ordering

## Acceptance rules

Only a schema-valid, size-bounded and correctly signed envelope reaches the replay guard. The production guard then revalidates the active tenant, subject membership, source and key tuple inside PostgreSQL and applies all state changes in one transaction.

Trusted database time is the receive time. An envelope is rejected when:

- `observedAt` is not earlier than `expiresAt`;
- `observedAt` is more than 30 seconds in the future;
- `observedAt` is older than the source's configured `maximum_age_seconds`;
- `expiresAt` is at or before receive time;
- the signed expiry window exceeds the source's configured maximum age;
- the tenant has already accepted the event ID;
- the source key epoch has already accepted the nonce;
- the source sequence equals or falls below that epoch's high-water mark; or
- a higher sequence carries an observation time earlier than the epoch's last accepted observation.

Sequence gaps are allowed, but sequence and observation time must move forward. Key rotation starts a new sequence and nonce epoch because the state key is `(tenant_id, source_id, key_id)`. Event IDs remain unique within the tenant across key rotations.

## Atomic state and concurrency

Migration `016_evidence_replay_and_ordering.sql` adds an execute-only `trust.apply_evidence_replay_guard` function. It locks the source key epoch's state row before checking the nonce, sequence and observation high-water marks. A transaction-scoped advisory lock serializes the same tenant/event ID even when different sources submit it concurrently. Acceptance inserts an append-only metadata receipt and advances the epoch state together, so a failed or concurrent request cannot partially advance the trust input stream.

The acceptance receipt table contains identifiers, hashes, timestamps and ordering metadata only. It does not contain the signed envelope or payload. Migration 017 stores the application-encrypted canonical envelope in a separate access-controlled table and requires both records to commit together.

## Observable rejections

Expected freshness, replay and ordering denials return a bounded internal reason from the database function and commit an append-only rejection record. Rejection records contain the tenant/source/key binding, sequence and timestamps, but event IDs and nonces are represented only by SHA-256 hashes. They never contain the raw envelope or payload. Direct application-role reads and writes are revoked; database operations can inspect the records for controlled diagnostics and metrics.

The public API does not reveal which rule failed. Every guard denial remains `422 EVIDENCE_REJECTED`, preventing source, key and replay-state enumeration. Database or guard inconsistency remains `503 SERVICE_UNAVAILABLE`.

`createInMemoryEvidenceReplayGuard` mirrors the rules for deterministic unit and route tests. It is not a multi-process production store and must not replace `createPostgresEvidenceReplayGuard` in a deployed ingestion service.

## Verification

Run `npm run evidence-replay:verify`. The gate runs evidence-service and API tests, then a rolled-back PostgreSQL scenario covering future skew, stale observations, expiry, excessive TTL, invalid windows, duplicate event IDs and nonces, repeated and lower sequences, backward observation time, state non-advancement, hash-only rejection records, append-only history and least-privilege table access.
