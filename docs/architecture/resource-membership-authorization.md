# Tenant resource and membership authorization

## Resource model

Migration `004_tenant_resources_and_membership_rules.sql` creates `app.resources` as the first tenant-owned SaaS record type. Every row has a composite `(tenant_id, resource_id)` primary key and a composite `(tenant_id, owner_subject_id)` foreign key to the owner's exact membership. A resource therefore cannot be assigned to a subject through a membership in another tenant.

The deterministic development seed creates one member-owned and one administrator-owned resource for both Tenant Alpha and Tenant Beta. Resource IDs are opaque `res_UUID` values. The rows contain synthetic names only.

## Actor-bound database context

Tenant-scoped application work starts a transaction and calls:

```sql
SELECT identity.set_tenant_actor_context($1, $2);
```

The two parameters come from the previously resolved trusted tenant context, never directly from request data. The setter rechecks that the tenant, subject and exact membership are active and that the membership has at least one tenant role. It installs both IDs with transaction-local settings. Releasing the connection after commit or rollback clears them.

Actor-aware row-level security evaluates current membership and roles on every statement. A role removal or membership suspension therefore changes access immediately rather than waiting for a cached session role. The database context is an enforcement adapter for trusted authentication results; exposing the setter as a client-selected tenant or subject switch is forbidden.

## Resource access rules

| Actor state | Resource access |
| --- | --- |
| Active `tenant-member` | Select, create, update and delete only resources they own in the bound tenant. |
| Active `tenant-admin` | Select and manage every resource in the bound tenant. |
| Missing role, inactive subject, suspended membership or suspended tenant | Actor context is denied and no resources are visible. |
| Valid member in another tenant | The guessed resource row is invisible and cannot be changed. |
| No transaction-local actor context | No tenant resource is visible. |

The database owner remains a privileged migration and provisioning boundary. Application connections use the constrained `tenant_trust_app` privilege set and forced row-level security.

## Membership and role rules

- Only an active tenant administrator can add, change or remove memberships and tenant-role assignments through the tenant runtime role.
- An ordinary tenant member cannot grant a role, including to themselves.
- A new membership requires an active platform subject.
- A new tenant-role assignment requires an active membership in that exact tenant.
- Suspending a membership keeps its roles and resources for recovery and audit, but makes them ineffective immediately.
- Each tenant must retain at least one active tenant administrator. Add a replacement administrator before removing or suspending the current final administrator.
- Platform-role assignments remain inaccessible to the tenant runtime role.

Tenant suspension and final teardown orchestration remain part of T2.9. This migration establishes the row and authority invariants those workflows must preserve.

## Verification

Run `npm run resource-membership:verify` after migration and demonstration provisioning. The verifier reuses one PostgreSQL session and proves owner-only member access, tenant-wide administrator access, cross-tenant identifier denial, member self-escalation denial, immediate promotion/demotion effects, last-administrator protection, suspended-membership denial and empty access after transaction reuse. All temporary membership and role changes roll back.
