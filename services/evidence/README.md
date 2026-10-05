# Evidence ingestion service

`@tenant-trust/evidence` owns the source-authenticated evidence boundary. It validates the signed-envelope contract and byte limits before database access, resolves exactly one active tenant/source/key/subject tuple, reconstructs the canonical unsigned JSON, recomputes its SHA-256 digest and verifies its Ed25519 signature.

The service returns only a bounded acceptance receipt. It does not persist raw payloads, publish outcome events, apply freshness/replay/order rules or calculate trust. Those responsibilities remain in T5.5 and later tasks. All verification denials are mapped to a uniform public response by the API endpoint; internal reason codes exist only for focused tests and controlled diagnostics.

`createPostgresEvidenceVerificationResolver` calls the execute-only PostgreSQL resolver added by migration 015. It never binds database authority from the submitted subject claim and never falls back to a key from another tenant or source.

Run `npm run evidence-ingestion:verify` for the focused service, API and PostgreSQL boundary checks.
