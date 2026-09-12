# Tenant isolation phase verification

`npm run tenant-isolation:verify` is the Phase 2 completion gate. It runs one repeatable scenario against the deterministic Tenant Alpha and Tenant Beta fixtures and stops at the first failed boundary.

## Scenario sequence

The gate performs these checks in order:

1. Reapply the idempotent demo seeds and verify both tenants, subjects, memberships, roles, resources and tenant-owned security configuration.
2. Verify actor-bound PostgreSQL queries on a reused connection, including empty access without context and denial of foreign tenant identifiers.
3. Verify resource ownership, membership state, administrator privileges and tenant-qualified configuration rules.
4. Run the cross-tenant tampering suite across the API-facing resolver boundary, PostgreSQL, Redis and NATS.
5. Write equal logical cache and lock names for both tenants and prove that trusted context creates different Redis keys.
6. Publish and receive tenant-specific NATS events with Tenant Alpha and Tenant Beta credentials, then prove that each credential cannot subscribe to the other tenant's subject.
7. Suspend a tenant inside a rolled-back database transaction and prove that existing and new actor contexts immediately lose access. Verify governed reactivation and irreversible soft teardown without retaining the lifecycle probe.

The provisioning step is safe to rerun. Database mutation probes use transactions that roll back. Redis probes use expiring keys and remove them before exit. NATS checks use short-lived live subscriptions and do not create durable consumers or retained scenario state.

## Failure meaning

A failure blocks Phase 2 completion. The step heading identifies the failed boundary, and the underlying verifier prints the specific assertion or service error. Fix that boundary and rerun the full phase gate so a partial pass is never treated as tenant-isolation verification.

This gate covers the implemented foundation. The HTTP API and application services do not exist yet, so future endpoint, worker and service-adapter implementations must extend the same scenario at their enforcement points.
