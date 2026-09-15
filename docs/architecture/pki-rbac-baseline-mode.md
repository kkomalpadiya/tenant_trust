# PKI plus RBAC baseline mode

## Purpose

`pki-rbac-baseline-v1` is Baseline B for later comparative evaluation. It authorizes from tenant-scoped X.509 identity, current authoritative tenant membership and the T4.4 role/action matrix. It intentionally does not read evidence, trust scores, trust thresholds or adaptive-policy results.

The mode is an evaluation baseline, not a claim that certificate possession alone is sufficient. Certificate identity, active tenant/subject/membership state, role eligibility, explicit tenant predicates and forced PostgreSQL row-level security must all agree. Sensitive operations retain the separate T4.5 additional-control boundary.

## Explicit selection

Application composition selects the exact closed identifier `pki-rbac-baseline-v1` through `selectAuthorizationMode`. The returned configuration is immutable and internally branded. A missing mode, unsupported identifier or copied lookalike object prevents API/repository construction.

Every API repository exposes its selected branded mode, and the Fastify application validates that declaration before registering routes. HTTP bodies and query strings cannot select or override the mode. Profile and record routes reject all query parameters before authentication, while the existing sensitive schemas reject their query controls and extra body fields.

## Decision boundary

For every operation, the baseline evaluator requires:

1. a branded tenant context resolved from gateway-authenticated certificate identity and current PostgreSQL authority;
2. authentication source `mtls-certificate`;
3. an exact action from the closed T4.4 matrix; and
4. an eligible role and scope, followed by the database resource boundary.

An ordinary matrix `allow` permits the operation to continue to its explicit tenant-qualified query under forced RLS. A matrix `deny` remains denial. A `requires-controls` result is not converted into allow: export and tenant administration may proceed only when the trusted internal sensitive-operation authorizer separately returns exact boolean `true`. Missing additional controls remain a uniform denial.

The decision records `adaptiveTrustUsed: false`, the fixed certificate policy, the fixed role-policy version and the immutable matrix row. No trust or evidence parameter exists in the evaluator signature, so this mode cannot silently consume adaptive inputs.

## Verification

`npm run pki-rbac-baseline:verify` checks exact and branded mode selection, rejection of caller-selected modes, certificate-only authentication, member/admin role differences, Alpha/Beta resource isolation, absence of adaptive inputs, and default denial when a sensitive control is missing. Authorization and API unit tests cover copied modes, trusted-session rejection, startup failure without a mode, ordinary-action enforcement and sensitive-operation metadata.

The foundation check runs this verifier after the gateway, tenant-isolation and sensitive-operation gates. Those preceding gates prove the tenant-specific certificate and protected internal-connection boundaries that feed this baseline.
