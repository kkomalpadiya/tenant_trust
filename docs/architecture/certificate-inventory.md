# Certificate inventory and lifecycle records

PostgreSQL is the authoritative off-chain store for certificate identity and current lifecycle state. A successful issuance creates one row in `identity.certificates` and one initial `issued` row in `identity.certificate_lifecycle_events` through `identity.record_certificate_issuance`. The security-definer function performs both inserts in the caller's transaction, so an issued certificate is never acknowledged with only one of those records present.

## Inventory model

Every certificate row has a tenant-qualified primary key and records the opaque certificate ID, target subject, tenant issuer, certificate profile, issuer-scoped serial number, SHA-256 fingerprint, canonical public-key SPKI digest, public-key algorithm, validity window, current state, requester, request/idempotency identities, correlation ID and the first/latest lifecycle event IDs. The allowed states are `active`, `revoked`, `expired` and `superseded`. Initial issuance creates an `active` row; renewal creates a new active row and permanently supersedes its predecessor.

The database enforces globally unique certificate and event IDs, globally unique fingerprints, issuer-scoped serial uniqueness and tenant-scoped request/idempotency uniqueness. Immutable X.509 identity and issuance fields cannot be rewritten. Expiry and subject indexes support later authentication and lifecycle scans without dropping tenant scope.

`identity.certificate_lifecycle_events` is append-only. Each event repeats the minimum certificate identity needed for a stable lifecycle audit projection and links to the inventory row. The initial event is `issued`, has state `active`, has no reason or causation event and uses the issuance request's idempotency identity. Renewal appends linked `renewed` and `superseded` events in the same transaction; revocation and expiry remain later guarded transitions.

## Write and read boundaries

Application SQL starts a transaction and calls `identity.set_tenant_actor_context` from authenticated context. It then passes verified public certificate metadata to `identity.record_certificate_issuance`. The function derives the tenant and requester from that transaction context, requires an active same-tenant subject and active same-tenant issuer, and permits only self-enrollment or tenant-administrator enrollment.

The `tenant_trust_app` role has `SELECT` plus execute access to the atomic recording function. It has no direct insert, update or delete privilege on either certificate table. Forced row-level security lets a member read only their own inventory/history and lets an active tenant administrator read all certificate records in that tenant. An unbound, inactive or foreign-tenant actor sees no rows.

Identical reuse of an idempotency key returns the original certificate and event IDs. Reuse with different certificate metadata fails as a conflict. Callers should check an existing idempotency result before asking the CA to sign again; the database conflict remains the final integrity control for races or retries.

## Application integration

`@tenant-trust/certificate-inventory` rechecks the normalized request, resolved context and verified certificate metadata before constructing the persistence record. It generates certificate, event and correlation IDs inside the trusted boundary and excludes both private keys and certificate PEM from the durable inventory shape.

`@tenant-trust/certificate-issuance` now requires a `recordIssuedCertificate` dependency. It returns the public certificate only after that writer confirms the durable certificate ID, lifecycle event ID and `active` state. A PostgreSQL adapter maps the record fields to `identity.record_certificate_issuance`; an unavailable or unconfirmed write fails the issuance request instead of returning an unaudited success.

## Verification

Run `npm run certificate-inventory:verify` after migrations and deterministic demo provisioning. The gate runs package tests and a rolled-back PostgreSQL scenario that proves:

- complete issuer, serial, fingerprint, subject, expiry, state and event metadata;
- atomic initial inventory and lifecycle rows;
- member-own versus administrator-wide visibility;
- no cross-tenant visibility or foreign-issuer recording;
- no direct table mutation;
- append-only lifecycle history;
- issuer serial uniqueness and conflicting-idempotency rejection; and
- stable IDs for an identical replay.
