# Sensitive export and administration demonstration operations

## Endpoints

T4.5 adds two certificate-authenticated Fastify operations without adding a client-selectable tenant:

| Route | Request limit | Result |
| --- | --- | --- |
| `POST /v1/tenant-records/export` | `Idempotency-Key: idem_<UUID>`; JSON body no larger than 4 KiB; 1–25 unique opaque record IDs; no query parameters or extra fields | All requested records or one uniform denial, plus server-derived operation metadata |
| `POST /v1/admin/membership-reviews` | `Idempotency-Key: idem_<UUID>`; JSON body no larger than 4 KiB; exactly one opaque subject ID; no query parameters or extra fields | Same-tenant membership state and roles, plus server-derived operation metadata |

Both routes reject malformed, duplicate, oversized and caller-extended requests before authentication or data access. A request body or query cannot supply tenant, actor, role, sensitivity, authorization result or operation ID.

## Authorization and tenant scope

The PostgreSQL adapter repeats the T4.3 transaction boundary: it assumes `tenant_trust_app`, binds the mTLS tenant and subject, loads authoritative active membership and roles, and resolves the branded tenant context. It then requires the T4.4 matrix row for the exact sensitive action to identify an eligible tenant administrator at tenant scope.

Matrix eligibility is deliberately insufficient. T4.6 first evaluates the explicitly selected `pki-rbac-baseline-v1` mode and requires its immutable `requires-controls` decision for the same tenant-admin matrix row. A trusted internal `sensitiveOperationAuthorizer` must then return exact boolean `true` for the context, action, baseline decision, matrix row, server operation ID and bounded request attributes. Missing callbacks, false values, tenant members and malformed decisions deny before the sensitive data query. This callback remains the fail-closed integration port for later adaptive policy and bound step-up; clients cannot provide it over HTTP.

Export SQL includes the context-derived tenant predicate and forced RLS. It returns data only when every requested ID is visible, so a mixed local/foreign or local/missing batch cannot reveal a partial result. Membership review also uses an explicit context-derived tenant predicate and returns one uniform denial for absent and foreign subjects.

## Operation identity and audit boundary

The repository hashes the client key and normalized request, then reserves a server-generated `op_<UUID>` inside the protected transaction. The receipt is scoped to the authenticated tenant, actor and action; the raw key, payload and resource IDs are never stored. An identical retry reuses the operation ID and sets `idempotentReplay: true`, while conflicting key reuse returns `409 IDEMPOTENCY_CONFLICT`. Reservation rolls back with authorization denial, query failure or timeout. Successful responses expose immutable metadata containing the operation ID, selected authorization-mode ID, action, context-derived tenant, authenticated requester and bounded target/count fields.

T4.8 now records the operation ID on each successful sensitive access outcome alongside the server-generated request and correlation IDs. Denied attempts retain the same request correlation, trusted actor/tenant, action, hashed resource scope and bounded reason without exposing a raw target or payload. The later Fabric phase will select and commit audit records; the PostgreSQL projection does not claim a ledger commitment. Until the additional-control authorizer is configured, the default is denial; the explicit PKI/RBAC baseline does not turn `requires-controls` into allow. The live T4.5 verifier uses an in-process verification-only authorizer to exercise the data path.

## Verification

`npm run sensitive-operations:verify` proves tenant-member denial, tenant-administrator success, Alpha/Beta separation, all-or-nothing export, foreign-subject denial, ignored forged identity headers, rejection of caller-selected tenant controls and server operation IDs against provisioned PostgreSQL data. `npm run request-outcomes:verify` proves those operation IDs join sanitized append-only access outcomes without recording payloads. `npm run request-safeguards:verify` proves identical replay, conflict rejection, session rejection, size limits and timeout rollback. `npm run test:api` covers request bounds, schema rejection, default denial, trusted callback inputs, tenant-qualified SQL, rollback and error normalization.
