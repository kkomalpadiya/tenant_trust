# Trusted tenant-context resolution

## Security invariant

Every tenant-scoped operation uses exactly one tenant ID derived from authenticated identity. Request headers, path parameters, query strings, request bodies, resource identifiers and cache entries are untrusted claims. They may agree with the authenticated tenant, but they can never select or replace it.

The runtime precedence is:

1. A trusted authentication adapter validates the credential or server-issued session and returns one tenant-bound subject identity.
2. PostgreSQL supplies the current tenant, subject, membership and tenant-role state for that exact `(tenant_id, subject_id)` pair.
3. The tenant-context resolver verifies the binding and lifecycle state, then creates one immutable context.
4. Every database transaction, cache key, message subject, policy input, resource lookup and audit record receives that context explicitly.
5. Any client or resource tenant claim is checked against the context. Missing authority, invalid state or any mismatch denies the operation.

There is no fallback to a default tenant, the first membership, a resource owner, a host name or a client-supplied `X-Tenant-Id` value.

## Trusted authentication inputs

The initial contract recognizes two authentication adapter outputs:

| Source | Required tenant binding |
| --- | --- |
| `mtls-certificate` | The validated certificate and issuer mapping bind one `subjectId` to one `tenantId`. Certificate validation, expiry and revocation checks precede tenant-context resolution. |
| `trusted-session` | A server-issued, integrity-protected session binds one `subjectId` to one `tenantId` and records the authentication event that created it. |

A subject with memberships in multiple tenants must authenticate into one tenant at a time. Tenant selection occurs only inside the authentication flow, after the server confirms that membership, and produces a new tenant-bound session. Changing a tenant in an ordinary API request never changes the session context.

The context package trusts the authentication adapter boundary; it does not prove that a caller labeled its input correctly. API code must construct the `authentication` object from verified server state, never by spreading or copying request JSON.

## Authoritative state and output

PostgreSQL remains authoritative for lifecycle and roles. Resolution requires all of the following to match the authenticated IDs and be active:

- tenant record and version;
- subject record and version;
- composite tenant membership and version;
- at least one tenant role on that membership.

The result contains only `tenantId`, `subjectId`, sorted tenant roles, authentication provenance and the three authority versions. It is frozen before it crosses into downstream code. Platform roles are excluded. A `platform-admin` uses a separate platform administration route and gains no tenant data context without an ordinary active tenant membership and role.

The recorded versions let later middleware detect stale derived context after suspension or role changes. They do not replace a required fresh database read, session invalidation or certificate-status check.

## Request and resource checks

Tenant-bearing input has one of two uses:

| Input | Required handling |
| --- | --- |
| Header, path, query or body tenant ID | Validate its shape when present and compare it with the resolved context. Reject mismatch. Never use it to choose a tenant. |
| Tenant-owned resource ID | Query by both trusted `tenantId` and resource ID. If a loaded internal record exposes its tenant ID, compare it before use. |

Foreign and missing resources use one tenant-safe external denial. `tenantSafeDenial` returns `403 ACCESS_DENIED` for every tenant-context error. Internal audit can retain a bounded reason code, correlation ID and trusted identifiers, but the response must not reveal whether the foreign tenant, subject or resource exists.

## Downstream propagation

All consumers receive context explicitly. Global mutable tenant state, ambient request headers and unqualified repository methods are forbidden.

- PostgreSQL: begin a transaction, call `identity.set_tenant_actor_context` with the trusted tenant and subject, use tenant-qualified statements and finish with commit or rollback. Forced row-level security rechecks active membership and roles and fails closed when either binding is absent. See [Database tenant isolation](database-isolation.md) and [Tenant resource and membership authorization](resource-membership-authorization.md).
- Redis: use `tenantCacheKey` and `tenantLockKey` from `@tenant-trust/tenant-context/redis`; both reject unbranded contexts and encode dynamic key segments.
- NATS: pass the context to messaging subject and durable-consumer helpers. The local broker separately restricts the two demonstration tenant credentials to exact tenant prefixes. See [Redis and NATS tenant isolation](runtime-tenant-isolation.md).
- OPA: include the exact context and current versioned state in complete decision input. Policy enforcement belongs to Phase 7.
- PKI and audit: resolve issuers and records from the same trusted tenant, never from caller-selected identifiers.

## Failure decisions

Resolution fails closed when authentication provenance is absent or untrusted, required IDs are missing or malformed, authoritative records disagree, lifecycle state is suspended, a state version is invalid, no tenant role exists, or any request/resource tenant claim conflicts.

Internal reason codes distinguish these cases for testing and tenant-safe audit. They are not public resource-discovery signals. Cache data never repairs or overrides a denial based on authoritative identity state.

## Verification boundary

The `@tenant-trust/tenant-context` tests prove the contract accepts a valid mTLS or tenant-bound session, returns an immutable context, rejects inactive and mismatched authoritative state, excludes platform-only authority, rejects tenant switches from every supported request/resource claim source and maps all failures to one external denial.

These tests do not prove that a future API validates certificates correctly, issues secure sessions or supplies complete OPA input. Database scoping and Redis/NATS runtime scoping are verified separately against the running services; future adapters must use those established boundaries consistently.
