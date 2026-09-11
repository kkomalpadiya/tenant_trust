# Tenant-owned security configuration

## Durable ownership model

Migration `005_tenant_security_configuration.sql` introduces four security configuration areas whose primary keys start with a non-null `tenant_id`:

| Table | Tenant-owned responsibility |
| --- | --- |
| `identity.tenant_issuer_mappings` | Maps one opaque `iss_UUID` to the tenant-specific certificate authority endpoint and lifecycle state. |
| `trust.evidence_sources` | Registers one opaque `src_UUID`, evidence type, freshness limit, verification method and optional issuer mapping. |
| `trust.trust_configurations` | Stores immutable numbered trust-model settings, including cold-start score, smoothing, source influence, staleness and the five evidence weights. |
| `trust.policy_versions` | Stores immutable `pol_UUID` bundle metadata, digest, entrypoint, lifecycle state and replacement lineage. |

Issuer and source mappings have stable identities. Trust settings and policy bundle contents cannot be rewritten after insertion; a changed model or bundle receives a new version. Partial unique indexes permit at most one active trust configuration per tenant and one active version of each named policy per tenant. Tenant-qualified foreign keys prevent an evidence source from referencing another tenant's issuer and prevent version provenance from naming a member outside the tenant.

## Runtime authorization

All four tables enable and force PostgreSQL row-level security for `tenant_trust_app`. An active member can read only the configuration for the actor-bound tenant. Only an active `tenant-admin` can insert, update or delete rows, and every write must retain the transaction's trusted tenant ID. A missing actor context returns no configuration rows. A guessed identifier from another tenant is invisible and cannot become write authority.

Database operations follow the existing transaction contract:

```sql
BEGIN;
SELECT identity.set_tenant_actor_context($1, $2);
-- read or administer the bound tenant's configuration
COMMIT;
```

The tenant and subject parameters come from trusted authentication resolution. Request data cannot select them.

## Demonstration boundary

The deterministic seed creates separate planned issuer mappings and five planned synthetic evidence sources for Tenant Alpha and Tenant Beta. It also stores one active trust configuration and one published policy version for each tenant. The tenants intentionally have different trust settings and bundle digests so an accidental cross-tenant lookup is visible.

These rows define ownership, integrity and lifecycle metadata only. A planned issuer is not an operational tenant CA, a planned source has no enrolled verification key, and a published policy is not active in OPA. Later PKI, evidence, trust and policy tasks must activate those components only after their own verification requirements pass.

## Verification

Run `npm run security-configuration:verify` after applying migrations and provisioning demo data. The verifier proves forced RLS and actor-aware policies, member read-only access, tenant-admin writes, cross-tenant identifier denial, tenant-qualified issuer references, immutable version content, one-active-version rules and empty access when the same connection is reused without context. All test writes roll back.
