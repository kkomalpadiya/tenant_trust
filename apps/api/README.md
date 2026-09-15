# Tenant Trust API

This workspace exposes the first certificate-authenticated SaaS endpoints:

- `GET /v1/profile` returns the authenticated subject's tenant profile.
- `GET /v1/tenant-records` returns records visible to the authenticated actor.
- `GET /v1/tenant-records/:recordId` returns one visible record or the uniform `403 ACCESS_DENIED` response.
- `POST /v1/tenant-records/export` returns an all-or-nothing export of 1–25 visible records after tenant-admin eligibility and a trusted internal control decision.
- `POST /v1/admin/membership-reviews` returns one same-tenant membership review after the same fail-closed sensitive-operation boundary.

Construct the application with `createTenantTrustApi`, a request authenticator created from the gateway identity resolver, and `createPostgresTenantRepository`. The API never accepts a tenant identifier in a route, query, or body. Its gateway adapter passes only the raw internal TLS socket and headers to `@tenant-trust/gateway-identity`; identity and tenant headers outside that resolver are not authority.

Every repository operation starts a PostgreSQL transaction, assumes the `tenant_trust_app` privilege set locally, binds the authenticated tenant and subject with `identity.set_tenant_actor_context`, loads the authoritative active tenant/membership/role state, resolves the immutable tenant context, and then queries with an explicit tenant predicate. Forced row-level security separately enforces tenant, ownership, administrator, and current membership rules.

Sensitive request bodies are limited to 4 KiB. Extra fields and query controls are rejected rather than stripped, and callers cannot provide tenant, role, sensitivity, authorization results or operation IDs. Sensitive routes default to denial unless the repository receives a trusted `sensitiveOperationAuthorizer`; even that callback is reached only for an authoritative tenant-admin matrix row. Successful results include a server-generated `op_<UUID>` for T4.8 audit-event correlation.

Run unit coverage with `npm run test:api`. With the migrated and provisioned local PostgreSQL service running, use `npm run profile-record-api:verify` for the live Alpha/Beta profile, ownership, administrator, guessed-record, and forged-header cases, and `npm run sensitive-operations:verify` for the bounded export, membership-review, default-deny and operation-ID cases.

Record writes, real baseline/adaptive authorizers, durable request-outcome capture, state freshness revalidation and state-changing administration remain outside this task's scope.
