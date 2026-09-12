# Tenant, subject and role data model

## Model boundary

PostgreSQL is the authoritative store for tenants, subjects, memberships and role assignments. A subject is a platform identity, not a tenant authorization. A subject gains tenant context only through an explicit membership identified by the composite key `(tenant_id, subject_id)`.

```text
subjects                         tenants
    |                               |
    |                               |
    +------ tenant_memberships -----+
                 |
                 +------ tenant_role_assignments

subjects ------ platform_role_assignments
```

Migration `002_tenant_subject_roles.sql` creates the following relations in the `identity` schema:

| Relation | Key and purpose |
| --- | --- |
| `tenants` | `tenant_id` primary key and a unique lowercase `tenant_slug`; owns tenant lifecycle state |
| `subjects` | `subject_id` primary key and unique `(identity_provider, provider_subject)`; identifies one human or service identity |
| `tenant_memberships` | Composite primary key `(tenant_id, subject_id)`; records whether a subject belongs to a tenant |
| `tenant_role_assignments` | Composite key `(tenant_id, subject_id, role_name)` and a composite foreign key to the matching membership |
| `platform_role_assignments` | Composite key `(subject_id, role_name)`; records platform operations authority separately from tenant roles |

The `tenant_id` and `subject_id` domains enforce the same prefixed UUID formats as the shared event contracts. Tenant-owned role rows cannot exist without the exact tenant-qualified membership. Foreign keys use restrictive deletion so a tenant, subject or membership cannot be silently removed while dependent authority remains.

## Role boundaries

`platform-admin` is a platform-scoped role. It may provision or suspend tenants and operate platform infrastructure through a dedicated platform administration path. It does not create a tenant membership and does not automatically grant access to tenant records, member profiles, tenant policy, evidence, trust state or certificate operations.

`tenant-admin` is a tenant-scoped role attached to one `(tenant_id, subject_id)` membership. It may manage membership and permitted certificate operations only inside that tenant. The same subject needs a separate membership and role assignment for every other tenant. A tenant administrator cannot grant platform roles, administer another tenant or select a different tenant through a request field.

`tenant-member` is also tenant-scoped. It represents ordinary membership and grants only the operations allowed by the tenant policy for that subject, resource and current security context.

Role assignment alone is never enough to authorize a request. Effective tenant access requires all of the following to be current and mutually consistent:

1. The platform subject is active.
2. The target tenant is active.
3. The exact tenant membership is active.
4. The required role is assigned on that membership.
5. Credential, resource, policy, request-context and trust checks pass.

Tenant runtime writes to memberships and tenant roles require an active `tenant-admin` actor context. New roles require an active membership, ordinary members cannot promote themselves, and a trigger prevents the final active tenant administrator from being removed or suspended. Suspended memberships retain their role rows for recovery and audit, but the roles grant no access.

The separate PostgreSQL enum types make `platform-admin` invalid in a tenant-role row and make tenant roles invalid in a platform-role row. Tenant-scoped subject events likewise carry only tenant roles; platform-role changes require a separate future platform administration contract rather than being smuggled into a tenant event.

## Uniqueness and lifecycle rules

- Tenant slugs are lowercase, bounded and globally unique for deterministic local routing and provisioning.
- External identities are unique by `(identity_provider, provider_subject)`; display names are not identifiers.
- A subject may have memberships in multiple tenants, but each membership and each assigned tenant role is unique within its tenant-qualified key.
- Each mutable lifecycle row has a positive version and ordered timestamps for later optimistic concurrency checks.
- Lifecycle states are `active` or `suspended`. Suspension preserves identifiers and relationships for later recovery and audit work. Irreversible teardown keeps the tenant suspended and adds `retired_at` rather than introducing a state that could accidentally pass an active-state check.

## Verification and later enforcement

Run `npm run infra:migrate` and then `npm run identity-model:verify`. The verifier inserts disposable records in a transaction, proves the tenant and external-identity uniqueness constraints, proves role assignments require the matching membership, proves platform and tenant roles cannot be mixed, proves dependent roles prevent membership deletion, and rolls the fixtures back.

## Deterministic development identities

`npm run demo:provision` creates the fixed local demonstration identities below. The seed is idempotent: rerunning it preserves existing lifecycle states and validates that its deterministic identifiers do not conflict with different records.

| Tenant | Subject | Tenant role |
| --- | --- | --- |
| Tenant Alpha | Alice | `tenant-member` |
| Tenant Alpha | Tenant Alpha Admin | `tenant-admin` |
| Tenant Beta | Bob | `tenant-member` |
| Tenant Beta | Tenant Beta Admin | `tenant-admin` |

The resource seed also creates one member-owned and one administrator-owned synthetic resource in each tenant. The separate Platform Operator subject receives `platform-admin` and no tenant membership. All seed identity records begin in the `active` state. The seeds contain no passwords, certificate material or production identity data.

Run `npm run demo:verify` to check the exact deterministic identity, role and resource mapping. The verifier also changes one tenant, subject and membership to `suspended`, checks their incremented versions, and rolls the transaction back so the baseline remains active.

[Trusted tenant-context resolution](tenant-context-resolution.md) defines how verified identity and this authoritative state produce one immutable tenant context while rejecting client-selected tenant switches. [Database tenant isolation](database-isolation.md) applies forced row-level security and verifies connection reuse. [Tenant resource and membership authorization](resource-membership-authorization.md) defines owner, administrator, role-change and membership-state enforcement. [Tenant suspension and teardown controls](tenant-lifecycle-controls.md) define the separate platform actor, immediate suspension, governed recovery and irreversible retained teardown boundary.
