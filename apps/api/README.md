# Tenant Trust API

This workspace exposes the first certificate-authenticated SaaS endpoints:

- `GET /v1/profile` returns the authenticated subject's tenant profile.
- `GET /v1/tenant-records` returns records visible to the authenticated actor.
- `GET /v1/tenant-records/:recordId` returns one visible record or the uniform `403 ACCESS_DENIED` response.

Construct the application with `createTenantTrustApi`, a request authenticator created from the gateway identity resolver, and `createPostgresTenantRepository`. The API never accepts a tenant identifier in a route, query, or body. Its gateway adapter passes only the raw internal TLS socket and headers to `@tenant-trust/gateway-identity`; identity and tenant headers outside that resolver are not authority.

Every repository operation starts a PostgreSQL transaction, assumes the `tenant_trust_app` privilege set locally, binds the authenticated tenant and subject with `identity.set_tenant_actor_context`, loads the authoritative active tenant/membership/role state, resolves the immutable tenant context, and then queries with an explicit tenant predicate. Forced row-level security separately enforces tenant, ownership, administrator, and current membership rules.

Run unit coverage with `npm run test:api`. With the migrated and provisioned local PostgreSQL service running, use `npm run profile-record-api:verify` for the live Alpha/Beta profile, ownership, administrator, guessed-record, and forged-header cases.

Write operations, generalized action policy, exports, administrative endpoints, and freshness-bounded revalidation are intentionally outside this workspace's current task scope.
