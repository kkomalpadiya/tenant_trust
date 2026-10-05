# Signed evidence envelope

## Contract boundary

`packages/contracts/schemas/evidence/signed-evidence-envelope.schema.json` defines the source-to-ingestion message for Phase 5. An evidence source creates this envelope before the system has accepted, stored or scored the observation. The separate `evidence.accepted.v1` and `evidence.rejected.v1` events remain ingestion outcomes and never carry the raw evidence payload.

The contract fixes the signed surface early so source enrollment, simulators, ingestion, replay protection and off-chain storage can share one representation. JSON Schema validates shape. It does not prove that a source is enrolled, that a signature is valid, that timestamps are fresh or that the claim is true.

## Required fields

| Field | Rule |
| --- | --- |
| `schemaVersion` | Exactly `1.0.0` |
| `eventId` | One immutable source event ID in canonical `evt_UUID` form |
| `tenantId` | Tenant claimed by the source; ingestion must match it to enrolled source state |
| `subjectId` | Subject observed by the source; ingestion must verify same-tenant membership |
| `sourceId` | Enrolled evidence-source identity used to resolve the verification key |
| `evidenceType` | `identity`, `device`, `behaviour`, `certificate` or `compliance` |
| `observedAt` | RFC 3339 UTC time when the source made the observation |
| `expiresAt` | RFC 3339 UTC time after which the observation cannot be accepted or scored |
| `sourceSequence` | Non-negative safe integer that increases within a source key epoch |
| `nonce` | 22 to 64 unpadded base64url characters, unique within that source key epoch |
| `synthetic` | Explicit marker separating simulated evidence from real observations |
| `payload` | Non-empty evidence-type-specific claims; raw bytes stay at the ingestion boundary |
| `signature` | Ed25519 algorithm, canonicalization profile, key ID, digest and signature value |

Both `sourceSequence` and `nonce` are signed. The sequence supports monotonic ordering and rollback detection. The nonce prevents two observations in the same sequence slot from becoming byte-identical and gives replay diagnostics a stable source-provided value. Later ingestion logic must reject duplicate IDs, nonces and conflicting or non-monotonic sequences.

## Canonical signing input

The `tenant-trust-evidence-json-v1` profile signs a deterministic projection of the envelope:

1. Remove the complete top-level `signature` object.
2. Serialize the remaining JSON using RFC 8785 JSON Canonicalization Scheme.
3. Encode that canonical JSON as UTF-8 without a byte-order mark.
4. Set `signedContentSha256` to the lowercase hexadecimal SHA-256 digest of those bytes.
5. Sign the same canonical bytes with Ed25519 and encode the 64-byte signature as unpadded base64url in `signatureBase64Url`.

The verifier reconstructs those bytes rather than trusting the transmitted digest. It resolves `signature.keyId` only inside the authoritative `(tenantId, sourceId)` enrollment. A key ID from another tenant or source is never tried as a fallback. The fixed algorithm and canonicalization values prevent algorithm downgrade and ambiguous serialization.

The raw envelope bytes, canonical bytes, digest and verification outcome must be treated as one immutable observation record. Services must not normalize a failed envelope and retry verification against different bytes.

## Processing invariants beyond JSON Schema

The ingestion service added in later Phase 5 tasks must enforce all of the following before acceptance:

- the source and selected key are active and enrolled for the claimed tenant;
- the subject exists, belongs to that tenant and is eligible for the evidence type;
- the signature and recomputed digest match the canonical unsigned envelope;
- `observedAt < expiresAt`, the observation is within allowed clock skew and it has not expired;
- the event ID, nonce and sequence do not replay, conflict or move the source backwards;
- the payload matches the selected evidence-type schema and its byte size is within policy;
- tenant/source rate limits and influence controls permit the observation.

A valid signature proves possession of an enrolled key. It does not establish that the source's claim is true. Trust calculation therefore remains separate and will use corroboration, source influence limits and explicit synthetic markers.

## Privacy and downstream events

Raw payloads stay off-chain and are not published on the ordinary event stream. After validation, ingestion stores the raw canonical observation through the tenant-scoped off-chain storage boundary and publishes only the accepted observation identity, source, type, times, sequence, synthetic flag and `contentHashSha256`. Rejections expose a bounded reason code rather than copying sensitive payload content into logs or events.

## Verification and task boundary

Run `npm run evidence-envelope:verify`. The tests compile the schema, accept all supported evidence types and reject missing identity, freshness, ordering or signature fields; malformed identifiers and timestamps; weak or ambiguous signature metadata; invalid sequence/nonce values; empty payloads; unknown fields and unsupported evidence types.

T5.1 defines the envelope. T5.2 implements source enrollment and key history. T5.3 provides deterministic signed synthetic fixtures for all five evidence types. T5.4 and T5.5 will implement cryptographic verification, trusted tenant/subject binding, freshness, replay and ordering checks.
