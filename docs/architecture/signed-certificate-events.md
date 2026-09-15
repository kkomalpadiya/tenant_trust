# Signed certificate lifecycle events

Certificate lifecycle events leave PostgreSQL through a transactional outbox and reach the tenant event stream with producer authentication. This boundary covers `certificate.issued.v1`, `certificate.renewed.v1`, `certificate.superseded.v1`, `certificate.revoked.v1` and `certificate.expired.v1`. It does not treat a signature as proof that the recorded lifecycle fact is true; consumers still bind the signed statement to authoritative tenant and certificate state.

## Atomic source records

Migration 011 attaches an `AFTER INSERT` trigger to the immutable `identity.certificate_lifecycle_events` table. Every lifecycle insert creates exactly one `identity.certificate_event_outbox` row in the same database transaction. A state transition therefore cannot commit without its pending delivery identity, and a rolled-back transition retains neither record. The migration also backfills pending outbox identities for lifecycle events created before the trigger existed.

The outbox retains the lifecycle `eventId`, claim state, attempt count, bounded failure code, acknowledged JetStream sequence and SHA-256 digest of the final signed event. It does not store a private key or duplicate the lifecycle payload. The NOLOGIN `tenant_trust_certificate_event_worker` role has no direct table privileges and can only call constrained security-definer functions.

## Expiry transition

The worker calls `identity.record_due_certificate_expiration` only after a certificate's authoritative `not_after` time. The function locks an active certificate, rejects early or non-active transitions, changes it permanently to `expired`, increments its version and appends `CERTIFICATE_EXPIRED` with the previous lifecycle event as its cause. An identical retry returns the existing durable expiry event. The insert automatically enters the same outbox path as issuance, renewal, supersession and revocation.

## Claim and delivery order

The publisher processes one tenant at a time:

1. Claim the oldest due event with an opaque claim token. `FOR UPDATE SKIP LOCKED` prevents two workers from owning the same row, and a claim older than five minutes is recoverable.
2. Read certificate and lifecycle fields returned by the claim function. The worker does not accept a client-provided tenant, certificate, actor, event or causal identity.
3. Build the versioned contract. Issuance starts a lifecycle chain with null causation. Renewal points to the predecessor event, revocation points to the event it terminates, supersession points to the matching renewal, and expiry points to the previous active event. Correlation IDs remain unchanged within their originating operation.
4. Sign the canonical unsigned envelope, publish it to `tenant.<tenantId>.events.<eventType>` with `eventId` as the NATS message ID, and wait for the JetStream acknowledgement.
5. Mark the exact active claim published with the server sequence and signed-event digest. An unavailable broker or invalid acknowledgement returns the row to pending with a bounded failure code and retry delay.

The path is at least once. A retry inside JetStream's duplicate window reuses the same message ID and is suppressed. A sufficiently late retry can create another stored message, so every consumer must keep durable `(consumer, eventId)` idempotency and reject conflicting content.

## Signature contract

`@tenant-trust/certificate-events` signs UTF-8 bytes produced by `tenant-trust-json-v1`: object keys are recursively sorted, arrays preserve order and values use JSON scalar encoding. The `sourceAuthentication` block contains:

- `algorithm: Ed25519`;
- `canonicalization: tenant-trust-json-v1`;
- a tenant- and producer-bound `keyId`;
- `signedContentSha256` for the unsigned canonical bytes; and
- the 64-byte signature encoded as unpadded base64url.

Verification first applies the event schema and exact tenant expectation, removes only `sourceAuthentication`, rebuilds the canonical bytes, compares the digest, resolves the public key using tenant, producer service, instance, key ID and algorithm, and verifies the Ed25519 signature. Payload changes, causal-ID changes, tenant substitution, producer substitution and untrusted keys fail before consumer effects.

Private keys stay outside Git, event payloads and PostgreSQL. The package accepts an asynchronous signer callback so a deployed worker can use an HSM or managed key service. The local verification generates an ephemeral key pair in memory. Production still needs protected key enrollment and rotation, service-specific NATS credentials, durable consumer receipts/inbox state, reconciliation metrics and operational alerting.

## Verification

Run `npm run certificate-events:verify`. The focused gate:

- validates the source-authentication and lifecycle contracts;
- tests canonicalization, signing, tenant/key binding, tamper rejection, acknowledgement ordering and parameterized repository calls;
- runs a rolled-back PostgreSQL scenario for issuance, renewal, supersession, revocation, expiry, atomic outbox creation, constrained claims, successful acknowledgement and retry state; and
- publishes signed disposable lifecycle events to the real local JetStream, consumes them through a tenant-filtered durable consumer and verifies every signature before acknowledging.
