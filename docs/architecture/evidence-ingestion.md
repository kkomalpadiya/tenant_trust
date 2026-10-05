# Signed evidence ingestion

## Endpoint boundary

`POST /v1/evidence` is registered when the SaaS API receives the branded `@tenant-trust/evidence` service. The route is authenticated by the signed envelope rather than by a human client certificate. Transport tenant, subject and authorization headers are not authority and the human mTLS identity resolver is not called.

The route limits the raw request body to 65,536 bytes. The service independently validates the complete `signed-evidence-envelope.schema.json` contract and limits the canonical payload to 32,768 bytes before any authoritative lookup. It rejects query parameters and returns only a bounded receipt containing the event, tenant, subject, source, evidence type, source sequence, synthetic marker and content hash. It never returns or logs the raw payload.

## Authoritative binding

Migration `015_evidence_ingestion_verification.sql` adds the execute-only `trust.resolve_evidence_verification_context` function. It resolves only an exact `(tenant_id, subject_id, source_id, key_id)` tuple where:

- the tenant, subject and membership are active;
- the evidence source and selected key are active;
- the source uses the enrolled Ed25519 fingerprint;
- the key belongs to that same tenant and source.

The function runs with row security disabled inside its fixed security-definer query, but it returns only this allowlisted verification material. The application role cannot turn a submitted subject claim into database actor authority, and the resolver never calls `identity.set_tenant_actor_context`. Missing, foreign, suspended, retired, rotated or revoked tuples all resolve as absent.

After lookup, the service also requires the authoritative evidence type and synthetic-source marker to match the signed envelope. It decodes the enrolled 32-byte public key, recomputes its SHA-256 fingerprint and never tries another tenant's or source's key as a fallback.

## Cryptographic verification

The service removes the complete `signature` object and serializes the remainder using the `tenant-trust-evidence-json-v1` RFC 8785 profile. It hashes those UTF-8 bytes with SHA-256, compares the result with `signedContentSha256`, decodes the canonical 64-byte signature and verifies Ed25519 against the exact enrolled key.

Schema and size failures occur before database access. A valid-shape envelope reaches acceptance only after binding, digest and signature verification. Public responses remain bounded:

| Condition | Response |
| --- | --- |
| Contract/schema failure | `400 INVALID_REQUEST` |
| Raw envelope or canonical payload too large | `413 REQUEST_TOO_LARGE` |
| Source, tenant, subject, key, digest or signature denial | `422 EVIDENCE_REJECTED` |
| Verification database unavailable or inconsistent | `503 SERVICE_UNAVAILABLE` |
| Verified envelope | `202` with the bounded acceptance receipt |

Internal reason codes are retained only inside the service for focused verification. They are not returned to an untrusted source and cannot be used to enumerate tenants, subjects, sources or keys.

## Task boundary and verification

T5.4 authenticates the source and validates schema, size and tenant/subject binding. It deliberately does not persist raw evidence, publish acceptance events, enforce observation-time freshness, reject duplicate IDs/nonces, enforce monotonic source sequences or calculate trust. T5.5 owns freshness, replay and ordering; T5.6 owns encrypted off-chain persistence.

Run `npm run evidence-ingestion:verify`. The gate executes the service and Fastify route tests, then runs a rolled-back PostgreSQL scenario proving exact resolution, cross-tenant/subject/key invisibility and revoked-key denial.
