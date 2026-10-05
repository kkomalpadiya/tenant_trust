# Evidence source enrollment and key registry

## Boundary and authority

An evidence source is first registered as tenant-owned `planned` metadata in `trust.evidence_sources`. Enrollment does not create an arbitrary source: it activates one of those existing records and binds its first Ed25519 verification key. The application service accepts no tenant, actor, fingerprint, lifecycle state or version from the caller. It derives tenant and actor from a resolved trusted context and requires `tenant-admin`.

PostgreSQL independently repeats the authorization check. The three registry functions derive the tenant and actor from transaction-local database context, lock the tenant-qualified source row and deny missing, foreign, retired or inconsistent targets with the same non-enumerating boundary. Ordinary members cannot enroll, rotate or revoke keys. Direct application-role changes to source lifecycle or key material are blocked.

## Public-key history

`trust.evidence_source_keys` stores public Ed25519 key material only. Every row is bound to `(tenant_id, source_id, key_id)`, has a monotonically increasing per-source `key_version`, and records the administrator and time that enrolled, rotated or revoked it. The registry verifies that the supplied unpadded base64url value decodes to exactly 32 bytes and derives its lowercase SHA-256 fingerprint from those bytes.

At most one key can be active for a source:

- `trust.enroll_evidence_source` creates version 1 and changes a planned source to active.
- `trust.rotate_evidence_source_key` marks the current active key as rotated and appends the next active version in the same transaction.
- `trust.revoke_evidence_source_key` marks the selected key revoked without deleting its public material. Revoking a historical key leaves the current key active. Revoking the active key suspends the source and clears its current-key fingerprint. A later rotation appends a recovery key and reactivates the source.

Rotation and revocation therefore change whether a key may authenticate new evidence, but they do not remove the public key needed to verify a historical envelope. Key identity, version, algorithm, public material, fingerprint and original enrollment provenance are immutable, and deletes are rejected. A later ingestion verifier must resolve a key only under the envelope's authoritative `(tenantId, sourceId, signature.keyId)` tuple and apply lifecycle time rules before accepting new evidence.

## Isolation and verification

The key table uses forced row-level security. Active tenant members can read only their own tenant's public key history; mutation is available only through the governed security-definer functions. Tenant-qualified foreign keys prevent a key or audit actor from crossing tenant boundaries.

Run `npm run evidence-sources:verify` after migrations and deterministic provisioning. It runs unit tests for authoritative context, exact request shape, Ed25519 key validation, server-generated key IDs, safe denials and parameterized repository calls. Its live PostgreSQL transaction proves member denial, administrator enrollment, cross-tenant denial, rotation, historical and active revocation, recovery rotation, forced RLS, direct-write denial and retained public-key history. All test mutations roll back.
