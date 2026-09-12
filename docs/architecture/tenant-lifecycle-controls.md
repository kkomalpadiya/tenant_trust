# Tenant suspension and teardown controls

Migration `006_tenant_lifecycle_controls.sql` adds a platform-only lifecycle boundary for suspension, governed reactivation and irreversible soft teardown. Tenant administrators cannot change their tenant's lifecycle state directly.

## Platform actor boundary

`tenant_trust_platform_admin` is a constrained `NOLOGIN`, non-superuser PostgreSQL role. A trusted platform administration path assumes it only after authentication, starts a transaction and calls:

```sql
SELECT identity.set_platform_actor_context($platform_subject_id);
```

The setter accepts only an active subject with the `platform-admin` role and stores the subject ID in transaction-local state. Reusing the connection after commit or rollback clears that binding. The role receives execute permission on the lifecycle functions and read-only access to lifecycle audit events. It receives no direct tenant-table write permission or tenant business-data access.

Tenant lifecycle commands require that actor binding and a contract-format reason code:

```sql
SELECT identity.suspend_tenant($tenant_id, 'TENANT_SECURITY_HOLD');
SELECT identity.reactivate_tenant($tenant_id, 'TENANT_SECURITY_REVIEW_COMPLETE');
SELECT identity.teardown_tenant($tenant_id, 'TENANT_RETENTION_STARTED');
```

Repeated suspension, reactivation or teardown requests are idempotent when the tenant is already in the requested state. A missing tenant returns the same denied lifecycle result as missing platform authority rather than revealing whether it exists.

## Suspension and reactivation

Suspension changes the authoritative tenant state to `suspended`, increments its version and appends a lifecycle event. PostgreSQL row-level security checks the live tenant state on every statement, so even an already-bound tenant session immediately loses access to identity, resource and security-configuration rows. New actor contexts are denied. The API-facing resolver and `revalidateTenantContext` likewise reject fresh authoritative state for a suspended tenant.

Suspension preserves memberships, roles, resources and security configuration for investigation and governed recovery. Reactivation increments the version and appends another event. It is permitted only before teardown.

Every request, cache read and event operation must revalidate tenant state or use an authority result produced for that operation. A stale context or cache value never overrides suspension. Tenant-facing code must not receive privileged database, Redis or NATS service credentials. Direct broker-credential shutdown and session/cache invalidation orchestration remain application-service responsibilities when those services are implemented.

## Irreversible soft teardown

Teardown requires the tenant to be suspended first. It then:

- Sets `retired_at`, which permanently blocks reactivation while leaving the tenant in the fail-closed `suspended` state.
- Deletes every tenant-role assignment so retained memberships cannot carry an effective privilege.
- Suspends and retains memberships because resources and immutable configuration history reference them.
- Retires issuer mappings and evidence sources.
- Supersedes active trust configurations and policy versions while retaining all immutable versions.
- Retains tenant resources and platform subject identities under their original tenant-qualified foreign keys.
- Rejects physical tenant deletion.

The teardown audit event records the platform actor, reason, resulting tenant version and counts of retained or retired records. The audit table and its tenant and actor references are append-only and deletion-restricted. This preserves the evidence needed to explain the offboarding decision without leaving orphaned rows or active tenant privileges.

## Verification

Run `npm run tenant-lifecycle:verify` after applying migrations and provisioning the deterministic demo data. The verifier uses one PostgreSQL session and rolls back every lifecycle change. It proves least-privilege grants, platform-actor binding, immediate loss of existing and new tenant access, governed reactivation, tenant-admin lifecycle denial, irreversible teardown, privilege removal, retained history, append-only audit and transaction-local connection cleanup.
