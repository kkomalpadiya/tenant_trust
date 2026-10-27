# JWT plus RBAC evaluation baseline

## Purpose

T10.4 implements Baseline A for later comparative evaluation. It provides a real signed-JWT authentication boundary and the existing Tenant Trust RBAC matrix while keeping the production SaaS API certificate-authenticated.

## Shared comparison scope

`@tenant-trust/evaluation` publishes one immutable `tenant-trust-comparison-workload-v1` catalog. Baseline A, Baseline B and the proposed framework all reference this exact workload ID and the same:

- Tenant Alpha and Tenant Beta identifiers;
- member and administrator subjects in each tenant;
- profile, record, export and tenant-administration resources;
- `profile:read`, `record:read`, `record:write`, `record:export` and `tenant:admin` actions; and
- member ownership, administrator tenant scope and cross-tenant denial probes.

This task fixes the comparator and workload identity. T10.5 will define the experimental protocol and labels, and later tasks will replay the catalog rather than inventing separate mode-specific workloads.

## Token boundary

The evaluation issuer signs compact JWTs with Ed25519 and the JOSE `EdDSA` algorithm. The protected header contains only `alg`, `kid` and `typ`. The payload contains only issuer, audience, token ID, tenant ID, subject ID, sorted role claims, issued-at, not-before and expiry. Token lifetime is bounded to 300 seconds.

The verifier rejects malformed or noncanonical base64url encoding, unknown header or claim fields, algorithm or key changes, signature tampering, wrong issuer/audience, duplicate or unknown roles, future activation, expiry and overlong lifetime. Authentication failures map to one safe `401 AUTHENTICATION_FAILED` result.

## Authorization boundary

After signature verification, the baseline creates a branded `trusted-session` context through `@tenant-trust/tenant-context`. Current tenant, subject and membership state must remain active and match the signed tenant and subject. Signed roles then select the existing `role-action-matrix-v1` row.

The target resource is checked separately against the matrix scope:

- `self` and `owner` require the authenticated subject and tenant;
- `tenant` requires the authenticated tenant; and
- `none` always denies.

For this pure JWT plus RBAC comparator, both `allow` and `requires-controls` matrix eligibility become allow after resource scope passes. That deliberately measures the security difference from Baseline B and the proposed framework: Baseline A does not use X.509 status, adaptive trust, OPA, bound step-up or Fabric audit. It also does not re-read authoritative role changes until the signed token expires. Tenant, subject and membership suspension is still checked on every evaluation request.

## Production separation

The JWT evaluator is an internal evaluation package. It does not register an HTTP route, add bearer-token handling, alter the mTLS gateway, or add `jwt-rbac-baseline-v1` to the production API authorization-mode selector. Existing API safeguards continue rejecting ambient `Authorization` headers.

## Verification

Run:

```text
npm run jwt-rbac-baseline:verify
```

The gate checks the shared comparison scope, EdDSA signing and verification, the complete workload oracle, sensitive administrator behavior, member ownership, cross-tenant denial, tampering, wrong keys, expiry, current membership enforcement and the absence of adaptive or certificate inputs.
