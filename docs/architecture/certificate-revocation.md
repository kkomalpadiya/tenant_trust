# Authorized certificate revocation

T3.7 implements permanent revocation across the request contract, trusted application boundary, mapped issuer and authoritative PostgreSQL inventory. A successful response means the exact certificate was confirmed revoked by the issuer and its terminal application state plus reasoned lifecycle event committed atomically.

## Request and authorization

The external request contains only `requestId`, `certificateId`, `reasonCode` and `idempotencyKey`. The boundary rejects caller-supplied tenant, subject, issuer, serial, fingerprint, event identity or revocation timestamp. Trusted tenant context supplies the tenant and actor, while the inventory supplies the certificate owner and issuer binding.

A subject may revoke their own active certificate. A same-tenant `tenant-admin` may revoke an active certificate owned by another subject in that tenant. An ordinary member cannot revoke another subject's certificate. Missing, foreign, revoked, expired or superseded targets use the same non-enumerating denial boundary.

The allowed reasons map to permanent RFC 5280 and Smallstep reason codes: key compromise, CA compromise, affiliation change, superseded, cessation of operation, privilege withdrawn and attribute-authority compromise. `CertificateHold` and `RemoveFromCRL` are excluded because Tenant Trust never restores a revoked certificate to active.

## Issuer confirmation

`@tenant-trust/certificate-revocation` resolves the active issuer from trusted tenant state and requires its allowed operations to include `revoke`. The issuer instruction carries the exact tenant, certificate, subject, issuer, canonical serial, SHA-256 fingerprint, approved application and CA reason codes, request identity and idempotency key.

The persistence call occurs only after an authenticated issuer adapter returns `revoked` with every target field and reason matching the instruction. The confirmation time cannot precede the request or exceed the trusted application clock by more than two seconds, and an opaque issuer confirmation reference is retained with the lifecycle event. Issuer errors and missing, malformed or mismatched confirmations cannot write a revoked state.

The local verification gate issues a disposable Smallstep certificate, actively revokes it through mTLS with `KeyCompromise`, and proves that Smallstep refuses its renewal. This proves the configured development CA execution path. The application inventory remains the authorization-time status authority described in [Certificate status validation](certificate-status-validation.md).

## Atomic durable transition

`identity.record_certificate_revocation` runs only through the constrained application role and uses transaction-local tenant and actor context. It first resolves an identical completed retry. A new request locks the exact tenant certificate, requires `active` state, confirms that the actor is the owner or a same-tenant administrator, requires an active matching issuer, and checks that the confirmed revocation time falls within the certificate validity period.

In one transaction the function changes the certificate to `revoked`, increments its version, points `last_event_id` to the new event and appends an immutable `revoked` lifecycle event. The event contains the reason, actor, request, correlation and idempotency identities, the previous lifecycle event as its cause, and the issuer confirmation reference. Any failure rolls back both changes.

The certificate-state trigger permits a transition only out of `active`. Once a certificate is `revoked`, `expired` or `superseded`, its terminal state cannot change. Lifecycle-event update/delete protection makes the revocation reason and confirmation append-only.

## Idempotency and recovery boundary

An identical retry returns the durable certificate, event, correlation, state and version without calling the issuer again. Reusing the idempotency key for another target, request, reason, actor or issuer confirmation is a conflict. A concurrent race still terminates at the locked database function and unique revocation indexes.

The synchronous prototype does not yet persist a `pending` issuer action. If the issuer is unavailable, no completed revocation is recorded and the request fails. The closed-loop orchestration phase must add durable requested/failed action state, immediate temporary access restriction and reconciliation before revocation is made asynchronous.

## Verification

Run `npm run certificate-revocation:verify` after migrations and demo provisioning. The gate validates request and event schemas, exercises application authorization and exact confirmation ordering, performs real disposable Smallstep revocation, and runs a rolled-back PostgreSQL scenario covering administrator and owner revocation, reason/event/confirmation persistence, stable replay, conflict rejection, foreign-tenant denial and terminal-state immutability.
