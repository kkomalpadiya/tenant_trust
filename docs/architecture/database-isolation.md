# Database tenant isolation

## Enforcement boundary

Migration `003_tenant_row_level_security.sql` adds a `tenant_trust_app` NOLOGIN role as the reusable tenant-runtime privilege set. It has no superuser, login, role-management, database-creation, replication or row-security bypass authority. A deployment login may inherit or assume this role only after trusted authentication and tenant-context resolution.

The runtime flow for every tenant-scoped database operation is:

1. Check out a connection and issue `BEGIN`.
2. Call `identity.set_tenant_context($1)` with the trusted context's tenant ID.
3. Run all tenant reads and writes inside that transaction.
4. Issue `COMMIT` or `ROLLBACK` before releasing the connection.

The setter accepts only a correctly typed, active tenant and stores it with PostgreSQL's transaction-local `set_config(..., true)`. Autocommit use is safe but useless because the binding expires when that statement ends. Application repositories must not use a session-level `SET`, retain a transaction across requests or release a connection before the transaction finishes.

## Row-level policies

Forced row-level security applies to the existing tenant-owned identity tables:

| Table | Runtime behavior |
| --- | --- |
| `identity.tenants` | Read and write only the row matching the bound tenant. |
| `identity.tenant_memberships` | Read and write only memberships whose `tenant_id` matches the binding. |
| `identity.tenant_role_assignments` | Read and write only role rows whose `tenant_id` matches the binding. |
| `identity.subjects` | Read only subjects with a membership in the bound tenant. Tenant runtime code cannot change the shared platform subject record. |

The runtime role receives no access to `identity.platform_role_assignments`. Migration and provisioning continue through the separate database owner connection. Row-level security is a defense against missing tenant predicates in application SQL; it does not replace authentication, role authorization, lifecycle checks or least-privilege service credentials.

Every future tenant-owned table must contain a non-null tenant-qualified key, enable and force row-level security, define matching `USING` and `WITH CHECK` policies, and add negative tests before its migration is complete.

## Connection reuse and failure behavior

`npm run database-isolation:verify` uses one PostgreSQL backend session for three consecutive transactions:

1. Tenant Alpha sees and can update only Alpha rows. A Beta update affects zero rows and a Beta insert is rejected.
2. The same session starts a new transaction without a binding and sees no tenant, membership, role or subject rows.
3. The same session binds Tenant Beta and sees only Beta rows.

The verifier also checks forced-RLS flags, policy ownership, runtime-role attributes and the absence of platform-role access. All fixture writes roll back. An absent context returns no rows; a malformed context raises an error; neither condition falls back to unrestricted access.
