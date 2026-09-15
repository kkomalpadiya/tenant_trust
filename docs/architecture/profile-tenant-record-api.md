# Profile and tenant-record API

T4.3 introduces the first protected Fastify routes in `apps/api`. They provide authenticated profile and tenant-record reads without adding a client-selectable tenant parameter.

## Request boundary

The production adapter sends only the request's raw internal TLS socket and headers to the gateway identity resolver. That resolver is the sole component allowed to interpret the gateway-owned certificate headers, and it returns the `mtls-certificate` authentication identity established by T4.1 and hardened by T4.2. Route code does not read `X-Tenant-ID`, `X-Subject-ID`, forwarded certificate headers, request bodies, or query strings as identity authority.

The implemented routes are:

| Route | Result |
| --- | --- |
| `GET /v1/profile` | The authenticated subject's display profile, tenant, tenant roles, membership date, and authority versions |
| `GET /v1/tenant-records` | Up to 100 records visible to the current actor, ordered by opaque record ID |
| `GET /v1/tenant-records/:recordId` | One visible record; missing, same-tenant unauthorized, and foreign-tenant IDs all return the same denial |

## Fail-closed data flow

For each operation, the PostgreSQL adapter performs this sequence on one checked-out connection:

1. Start a transaction and use `SET LOCAL ROLE tenant_trust_app`.
2. Call `identity.set_tenant_actor_context` with only the tenant and subject from authenticated gateway identity. The function rejects inactive tenants, subjects, memberships, and actors without a tenant role.
3. Read the exact authoritative tenant, subject, membership, versions, and tenant roles through forced RLS.
4. Resolve the branded immutable context with `@tenant-trust/tenant-context`.
5. Execute the profile or record query with an explicit context-derived tenant predicate while forced actor-aware RLS independently limits rows by tenant, ownership, and tenant-administrator status.
6. Commit on success; roll back on every denial or error. The transaction-local role and actor settings cannot leak to a reused connection.

Malformed record IDs return `400 INVALID_REQUEST`. Gateway identity failures return uniform `401 CLIENT_CERTIFICATE_REQUIRED`. Inactive, unauthorized, absent, and invisible resources return uniform `403 ACCESS_DENIED`. Unexpected authority or repository failures return `503 SERVICE_UNAVAILABLE` without internal error details.

## Verification boundary

`npm run test:api` checks route input handling, gateway-adapter inputs, transaction ordering, tenant-qualified SQL, rollback, error normalization, and resistance to forged ambient identity headers. `npm run profile-record-api:verify` uses the provisioned PostgreSQL database and Fastify injection to prove that an Alpha member sees only their record, an Alpha administrator sees both Alpha records, a Beta member sees only their Beta record, and guessed same-tenant or cross-tenant record IDs are indistinguishable denials.

The live API check injects an already authenticated `mtls-certificate` result because the full cryptographic gateway path is independently exercised by `npm run gateway-spoofing:verify`. It does not replace that gateway check. T4.4 will add the generalized read/write action policy; T4.7 will add freshness-bounded certificate, membership, and restriction revalidation.
