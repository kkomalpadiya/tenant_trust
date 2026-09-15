# Role, action and sensitivity contract

`@tenant-trust/authorization` is the canonical RBAC eligibility matrix for protected SaaS operations. It accepts only the branded tenant context returned by `@tenant-trust/tenant-context`, so request headers, certificate headers and caller-provided role arrays cannot select an authorization rule.

It also exposes the explicit `pki-rbac-baseline-v1` mode used by Baseline B. `selectAuthorizationMode` accepts only that exact internal identifier and returns one immutable branded configuration. `evaluateAuthorizationMode` requires gateway-derived `mtls-certificate` context, evaluates the matrix and records that adaptive trust was not used. Missing, unsupported and copied mode objects fail closed.

The matrix classifies profile read, record read, record write, record export and tenant administration. Resource type and sensitivity are derived from the action; callers cannot supply or downgrade them. Tenant-member access is limited to self or owned resources. Tenant-administrator record access is tenant-wide, but the platform-administrator role is deliberately outside this tenant matrix and has no implicit tenant-data grant.

`allow` means that the role is eligible at the recorded scope. It is not a complete request authorization: certificate status, current membership, resource binding, request context and later OPA/trust controls still have to pass. `requires-controls` is non-allowing and must never be treated as success. Export and administration use that disposition for eligible tenant administrators until an operation policy, subject/tenant/session/action-bound step-up proof and audit control are implemented. Every missing or unknown rule returns an immutable default denial.

Run `npm run role-action-matrix:verify` to check the exhaustive two-role-by-five-action matrix, fixed sensitivity classifications, administrator precedence, protected-context requirement, explicit baseline selection and default-deny behavior. Run `npm run pki-rbac-baseline:verify` for the live Alpha/Beta API boundary.
