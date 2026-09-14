# Certificate renewal and key rotation

T3.5 implements renewal as a fresh certificate issuance plus one atomic inventory transition. Renewal is not an extension or reactivation of the existing row: the predecessor becomes permanently `superseded`, the successor becomes `active`, and both facts receive distinct append-only lifecycle event IDs.

## Eligibility policy

The application accepts a renewal only when all of these conditions hold:

- authenticated tenant context is active and the target subject and membership are active;
- the caller is the subject or a same-tenant `tenant-admin`;
- the predecessor belongs to that tenant and subject, uses `tenant-client-auth-v1`, and is currently `active`;
- the predecessor has not expired and the request is in the final 25 percent of its validity window;
- the active tenant issuer allows `renew`; and
- trusted CSR inspection reports the declared algorithm and a canonical SPKI SHA-256 digest different from the predecessor key.

Suspended tenants, subjects or memberships fail at the membership boundary. Revoked, expired and already-superseded certificates fail the active-predecessor check. Unknown and foreign certificate IDs use the same non-enumerating denial response. Renewal never changes a predecessor back to active.

## Key rotation and certificate verification

The client generates a new private key and CSR locally. A trusted CSR parser verifies the CSR and returns the canonical SubjectPublicKeyInfo digest before the signer is called. Reusing the predecessor key is therefore rejected before certificate creation. The signer receives the expected new digest and predecessor digest but never the private key.

After signing, `@tenant-trust/certificate-issuance` repeats all identity, SAN, usage, validity, signature and issuer checks from initial issuance. It also hashes the returned leaf public key and requires an exact match with the pre-signing CSR inspection. The public SPKI digest is persisted so the next rotation can be compared without storing a certificate PEM or private key.

## Atomic supersession

`identity.record_certificate_renewal` is the final authorization and concurrency boundary. It revalidates active actor, target membership, issuer, predecessor ownership/state, renewal window and a different SPKI digest. The predecessor row is selected `FOR UPDATE`, preventing two concurrent renewals from both succeeding.

In one transaction the function:

1. inserts the active successor with `supersedes_certificate_id` pointing to the predecessor;
2. appends a `renewed` event for the successor, caused by the predecessor's last event;
3. updates the predecessor to `superseded` with a new last-event ID and incremented version; and
4. appends a `superseded` event for the predecessor, caused by the renewal event and carrying `CERTIFICATE_RENEWED`.

Any failure rolls back all four effects. Identical idempotent replay returns the durable successor and both event IDs; conflicting reuse is rejected.

## Verification

Run `npm run certificate-renewal:verify` after migrations and demo provisioning. It runs issuance and inventory unit tests, a live Smallstep scenario with a genuinely rotated P-256 key, and a rolled-back PostgreSQL scenario. The database gate covers early, same-key, revoked, suspended, already-superseded and foreign-tenant denial; successor/predecessor state; causal lifecycle events; and stable idempotent replay.
