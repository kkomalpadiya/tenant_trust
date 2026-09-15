# Role, action and resource-sensitivity matrix

## Boundary

T4.4 defines the role eligibility contract consumed by later API and policy-enforcement tasks. T4.6 wraps it in the explicit `pki-rbac-baseline-v1` mode, which requires tenant-scoped certificate authentication and deliberately uses no adaptive trust input. T4.5 sensitive rows still pass through a separate fail-closed internal authorizer port; neither the matrix nor the baseline claims that OPA, trust thresholds or bound step-up authentication are implemented.

The resolver accepts only an immutable tenant context produced from gateway-authenticated certificate identity and authoritative active tenant, subject, membership and role state. It never accepts a role, tenant, subject, resource type or sensitivity from request input. PostgreSQL forced row-level security remains the authoritative resource-scope check.

## Matrix

| Role | Action | Resource | Sensitivity | Scope | RBAC disposition |
| --- | --- | --- | --- | --- | --- |
| Tenant member | `profile:read` | Subject profile | Confidential | Self | Allow eligibility |
| Tenant member | `record:read` | Tenant record | Confidential | Owner | Allow eligibility |
| Tenant member | `record:write` | Tenant record | Confidential | Owner | Allow eligibility |
| Tenant member | `record:export` | Tenant record export | Sensitive | None | Deny |
| Tenant member | `tenant:admin` | Tenant administration | Critical | None | Deny |
| Tenant administrator | `profile:read` | Subject profile | Confidential | Self | Allow eligibility |
| Tenant administrator | `record:read` | Tenant record | Confidential | Tenant | Allow eligibility |
| Tenant administrator | `record:write` | Tenant record | Confidential | Tenant | Allow eligibility |
| Tenant administrator | `record:export` | Tenant record export | Sensitive | Tenant | Require additional controls; not an allow |
| Tenant administrator | `tenant:admin` | Tenant administration | Critical | Tenant | Require additional controls; not an allow |

Platform administration is intentionally absent. Infrastructure authority does not confer tenant business-data access.

## Fail-closed rules

- An unknown or malformed action resolves to a generic immutable denial without reflecting attacker input.
- A copied or caller-built context is rejected; only the branded trusted tenant context is accepted.
- Tenant administrators with multiple tenant roles resolve deterministically to the administrator row, never by caller ordering.
- `requires-controls` is non-allowing. Export and administration require operation policy, real action-bound step-up and an audit record before a later enforcement task can authorize them.
- An `allow` row establishes role eligibility only. Certificate status, active identity state, tenant/resource scope, request context and applicable policy remain mandatory, and any missing input denies.

The executable source is `packages/authorization/src/index.mjs`. `npm run role-action-matrix:verify` proves the complete matrix, mode-selection and denial invariants. `npm run pki-rbac-baseline:verify` proves live Baseline B behavior.
