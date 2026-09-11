# Database tenant isolation

## Enforcement boundary

Migration `003_tenant_row_level_security.sql` adds a `tenant_trust_app` NOLOGIN role as the reusable tenant-runtime privilege set. It has no superuser, login, role-management, database-creation, replication or row-security bypass authority. A deployment login may inherit or assume this role only after trusted authentication and tenant-context resolution.

The runtime flow for every tenant-scoped database operation is:

1. Check out a connection and issue `BEGIN`.
2. Call `identity.set_tenant_actor_context($1, $2)` with the trusted context's tenant and subject IDs.
3. Run all tenant reads and writes inside that transaction.
4. Issue `COMMIT` or `ROLLBACK` before releasing the connection.

The actor setter accepts only a correctly typed active tenant, active subject, active exact membership and at least one tenant role. It stores both IDs with PostgreSQL's transaction-local `set_config(..., true)`. Autocommit use is safe but useless because the binding expires when that statement ends. Application repositories must not use a session-level `SET`, accept either ID directly from request data, retain a transaction across requests or release a connection before the transaction finishes.

## Row-level policies

Forced row-level security applies to the existing tenant-owned identity tables:

| Table | Runtime behavior |
| --- | --- |
| `identity.tenants` | Active members read the bound tenant; only its active tenant administrators can update it. |
| `identity.tenant_memberships` | Active members read memberships in the bound tenant; only its active tenant administrators can change them. |
| `identity.tenant_role_assignments` | Active members read tenant roles; only active tenant administrators can change them. |
| `identity.subjects` | Read only subjects with a membership in the bound tenant. Tenant runtime code cannot change the shared platform subject record. |
| `app.resources` | Active members see and manage only owned rows; active tenant administrators see and manage all rows in the bound tenant. |

The runtime role receives no access to `identity.platform_role_assignments`. Migration and provisioning continue through the separate database owner connection. Row-level security is a defense against missing tenant predicates in application SQL; it does not replace authentication, role authorization, lifecycle checks or least-privilege service credentials.

Every future tenant-owned table must contain a non-null tenant-qualified key, enable and force row-level security, define matching actor-aware `USING` and `WITH CHECK` policies, and add negative tests before its migration is complete. See [Tenant resource and membership authorization](resource-membership-authorization.md) for the first protected SaaS record type.

## Connection reuse and failure behavior

`npm run database-isolation:verify` uses one PostgreSQL backend session for three consecutive transactions:

1. The Tenant Alpha administrator sees and can update only Alpha identity rows. A Beta update affects zero rows and a Beta insert is rejected.
2. The same session starts a new transaction without an actor binding and sees no tenant, membership, role or subject rows.
3. The same session binds the Tenant Beta administrator and sees only Beta identity rows.

The verifier also checks forced-RLS flags, policy ownership, runtime-role attributes and the absence of platform-role access. `npm run resource-membership:verify` separately exercises resource ownership, administrator scope and live membership/role changes. All fixture writes roll back. An absent context returns no rows; a malformed or unauthorized context raises an error; neither condition falls back to unrestricted access.
