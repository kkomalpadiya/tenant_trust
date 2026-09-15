# Sensitive export and administration demonstration operations

## Endpoints

T4.5 adds two certificate-authenticated Fastify operations without adding a client-selectable tenant:

| Route | Request limit | Result |
| --- | --- | --- |
| `POST /v1/tenant-records/export` | JSON body no larger than 4 KiB; 1–25 unique opaque record IDs; no query parameters or extra fields | All requested records or one uniform denial, plus server-derived operation metadata |
| `POST /v1/admin/membership-reviews` | JSON body no larger than 4 KiB; exactly one opaque subject ID; no query parameters or extra fields | Same-tenant membership state and roles, plus server-derived operation metadata |

Both routes reject malformed, duplicate, oversized and caller-extended requests before authentication or data access. A request body or query cannot supply tenant, actor, role, sensitivity, authorization result or operation ID.

## Authorization and tenant scope

The PostgreSQL adapter repeats the T4.3 transaction boundary: it assumes `tenant_trust_app`, binds the mTLS tenant and subject, loads authoritative active membership and roles, and resolves the branded tenant context. It then requires the T4.4 matrix row for the exact sensitive action to identify an eligible tenant administrator at tenant scope.

Matrix eligibility is deliberately insufficient. A trusted internal `sensitiveOperationAuthorizer` must return exact boolean `true` for the context, action, immutable matrix row, server operation ID and bounded request attributes. Missing callbacks, false values, tenant members and malformed decisions deny before the sensitive data query. This callback is the fail-closed integration port for the later baseline and adaptive-policy tasks; clients cannot provide it over HTTP.

Export SQL includes the context-derived tenant predicate and forced RLS. It returns data only when every requested ID is visible, so a mixed local/foreign or local/missing batch cannot reveal a partial result. Membership review also uses an explicit context-derived tenant predicate and returns one uniform denial for absent and foreign subjects.

## Operation identity and audit boundary

Each role-eligible attempt receives a server-generated `op_<UUID>` identifier before the internal control decision. Successful responses expose an immutable metadata object containing the operation ID, action, context-derived tenant, authenticated requester and bounded target/count fields. IDs are neither accepted from clients nor derived from resource identifiers.

These identifiers make later outcome events correlatable, but T4.5 does not claim durable audit capture. T4.8 will record authentication and access outcomes, and the later Fabric phase will select and commit audit records. Until a real authorizer is configured, the production default is denial; the live T4.5 verifier uses an in-process verification-only authorizer to exercise the data path.

## Verification

`npm run sensitive-operations:verify` proves tenant-member denial, tenant-administrator success, Alpha/Beta separation, all-or-nothing export, foreign-subject denial, ignored forged identity headers, rejection of caller-selected tenant controls and unique server operation IDs against provisioned PostgreSQL data. `npm run test:api` covers request bounds, schema rejection, default denial, trusted callback inputs, tenant-qualified SQL, rollback and error normalization.
