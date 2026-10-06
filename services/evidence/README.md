# Evidence ingestion service

`@tenant-trust/evidence` owns the source-authenticated evidence boundary. It validates the signed-envelope contract and byte limits before database access, resolves exactly one active tenant/source/key/subject tuple, reconstructs the canonical unsigned JSON, recomputes its SHA-256 digest and verifies its Ed25519 signature.

After signature verification, the service encrypts the complete canonical signed envelope with tenant-derived AES-256-GCM key material and requires an atomic replay guard. The PostgreSQL guard checks trusted receive time, the source TTL, expiry, duplicate event IDs and nonces, and monotonic source sequence and observation time within one tenant/source/key epoch. It records accepted replay metadata and application-encrypted evidence in the same transaction, while rejection diagnostics retain hash-only identifiers. The in-memory guard is for deterministic tests and single-process development only.

The service returns only a bounded acceptance receipt. Raw plaintext is never returned or stored, and the service does not yet publish outcome events or calculate trust. All verification denials are mapped to a uniform public response by the API endpoint; internal reason codes exist only for focused tests and controlled diagnostics.

`createPostgresEvidenceVerificationResolver` calls the execute-only PostgreSQL resolver added by migration 015. It never binds database authority from the submitted subject claim and never falls back to a key from another tenant or source. `createPostgresEvidenceReplayGuard` calls the atomic guard added by migration 016 and the encrypted store added by migration 017 in one transaction. `createPostgresEvidenceStorageRepository` binds an active database actor before every retrieve, delete or retention operation.

Run `npm run evidence-ingestion:verify` for signature ingestion, `npm run evidence-replay:verify` for freshness and ordering, and `npm run evidence-storage:verify` for encrypted persistence, access, retention and deletion.
