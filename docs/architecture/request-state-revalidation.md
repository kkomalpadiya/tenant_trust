# Per-request certificate and tenant-state revalidation

## Boundary

Every protected API operation revalidates current certificate, tenant, subject and membership state inside a new PostgreSQL transaction. Reusing an HTTP identity object, TLS connection or pooled database connection never reuses an earlier allow decision.

The fixed `authoritative-per-request-state-v1` policy has a five-second maximum state age, two-second future-clock tolerance and no cross-request allow cache. The API refuses repositories that do not declare this exact internal policy object.

## Request sequence

After the gateway has authenticated the client certificate, the repository:

1. starts a transaction, assumes `tenant_trust_app` locally and binds the gateway-derived tenant and subject;
2. loads current tenant, subject, membership, role and version state through forced RLS;
3. resolves the branded tenant context, which rejects inactive tenant, subject or membership state;
4. matches the presented certificate's tenant, subject, issuer, profile, serial, fingerprint and validity timestamps to one inventory row;
5. applies `application-status-v1` to an exact fresh inventory lookup; and
6. checks the five-second deadline again immediately before every protected data query.

Only a fresh `active` certificate continues. Revoked, superseded, expired, unknown or mismatched certificates return `401 CERTIFICATE_NOT_ACCEPTED`. Missing, stale, malformed, timed-out or unavailable authoritative state returns `503 SERVICE_UNAVAILABLE`. Tenant, subject, membership, role and resource denials remain the uniform `403 ACCESS_DENIED` response. T4.8 records the bounded result under the already authenticated tenant/actor and server-generated request correlation without storing certificate material or error text.

The protected query still uses an explicit context-derived tenant predicate and forced actor-aware RLS. Consequently, a tenant or membership change committed after the initial authority read is independently enforced by the data query. Certificate changes are observed on the next request and never later than the fixed in-request freshness deadline.

## Verification

`npm run request-state:verify` uses one Fastify application identity and one reused PostgreSQL backend. It proves that a membership suspension, tenant suspension and certificate revocation affect the next request, then restores seeded tenant state and removes all disposable certificate rows. Unit tests cover exact certificate binding, stale and unavailable state, copied policy rejection, deadline expiry and safe HTTP mappings.
