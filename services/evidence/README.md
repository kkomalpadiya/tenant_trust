# Evidence ingestion service

`@tenant-trust/evidence` owns the source-authenticated evidence boundary. It validates the signed-envelope contract and byte limits before database access, resolves exactly one active tenant/source/key/subject tuple, reconstructs the canonical unsigned JSON, recomputes its SHA-256 digest and verifies its Ed25519 signature.

After signature verification, the service requires an atomic replay guard. The PostgreSQL guard checks trusted receive time, the source TTL, expiry, duplicate event IDs and nonces, and monotonic source sequence and observation time within one tenant/source/key epoch. It records accepted replay metadata and hash-only rejection diagnostics without storing the raw payload. The in-memory guard is for deterministic tests and single-process development only.

The service returns only a bounded acceptance receipt. It does not persist raw payloads, publish outcome events or calculate trust. Those responsibilities remain in T5.6 and later tasks. All verification denials are mapped to a uniform public response by the API endpoint; internal reason codes exist only for focused tests and controlled diagnostics.

`createPostgresEvidenceVerificationResolver` calls the execute-only PostgreSQL resolver added by migration 015. It never binds database authority from the submitted subject claim and never falls back to a key from another tenant or source. `createPostgresEvidenceReplayGuard` calls the execute-only atomic guard added by migration 016 and commits expected rejection records so they remain observable.

Run `npm run evidence-ingestion:verify` for the signature-ingestion checks and `npm run evidence-replay:verify` for the freshness, replay, ordering and rejection-observability checks.
