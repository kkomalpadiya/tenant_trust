# Encrypted evidence storage

T5.6 stores the complete signed evidence envelope as canonical UTF-8 JSON in PostgreSQL, which is the prototype's authoritative off-chain store. The service encrypts those bytes before the database call with AES-256-GCM. PostgreSQL receives only ciphertext, a random 96-bit IV, the authentication tag, bounded verification metadata and a key identifier; it never receives the master key or plaintext envelope.

`createEvidenceProtector` derives a distinct 256-bit tenant key from the configured 32-byte master key with HKDF-SHA-256. Authenticated additional data binds the ciphertext to its tenant, subject, source, event, signed-content hash, format version, cipher and encryption-key ID. Retrieval decrypts the bytes, verifies the GCM tag, checks the full-envelope SHA-256 digest, parses and re-canonicalizes the envelope, and recomputes the unsigned signed-content digest before returning canonical bytes.

## Atomic acceptance

The PostgreSQL replay adapter calls `trust.apply_evidence_replay_guard` and `trust.store_encrypted_evidence` in one transaction. A deferred constraint trigger on every accepted receipt verifies that its encrypted-storage row exists before commit. A storage failure therefore rolls back both the ciphertext and accepted replay state; an accepted receipt cannot be committed with missing raw evidence.

## Access and lifecycle

The application role has no direct table privileges on `trust.encrypted_evidence`. Execute-only functions enforce these rules:

- An active subject may retrieve their own active, unexpired evidence.
- An active tenant administrator may retrieve evidence for subjects in the same tenant.
- Cross-tenant and unrelated-member lookups return no row.
- Only a tenant administrator may delete evidence or run that tenant's retention sweep.

Retention is fixed at 30 days from the trusted acceptance timestamp. Expired evidence is unavailable even before a sweep runs. Deletion and retention purge clear the ciphertext, IV, authentication tag, cipher and encryption-key ID while retaining a bounded tombstone containing identifiers, hashes, size, timestamps and reason. This makes deletion observable without leaving decryptable evidence behind.

## Key configuration

`EVIDENCE_STORAGE_MASTER_KEY` is a canonical base64url-encoded 32-byte secret. `npm run infra:init` generates it in the ignored local `.env`; it must not be committed. `EVIDENCE_STORAGE_KEY_ID` identifies the active key version and defaults to `local-evidence-v1`. A deployed environment should inject both values from its secret manager and retain old key material until evidence encrypted under that key has expired or been deleted.

Run `npm run evidence-storage:verify` to exercise encryption, canonical retrieval, tenant access, retention, deletion and the PostgreSQL controls.
