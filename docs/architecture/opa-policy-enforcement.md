# OPA policy enforcement

## Boundary

T7.2 connects all five certificate-authenticated SaaS operations to the versioned T7.1 OPA contract under the explicit `adaptive-trust-opa-v1` authorization mode. The existing `pki-rbac-baseline-v1` path remains available unchanged for later comparative evaluation. The evidence-ingestion endpoint uses its own signed-source boundary and is not a human protected route.

The enforcement adapter sends `POST /v1/data/tenant_trust/authorization/decision` with exactly `{ "input": ... }`. It accepts only one schema-valid `result`, verifies the echoed request, correlation, tenant, subject, input hash and certificate/tenant/subject/membership/trust versions, requires an exact match to the tenant's active policy ID/version/digest/entrypoint, and requires a decision timestamp no earlier than the request. Network errors, non-success responses, invalid JSON, partial results, missing active policy and binding mismatches fail closed.

## Evaluation order

Each protected operation uses this order:

1. Reject ambient browser or bearer sessions and authenticate the gateway-bound client certificate.
2. Begin the tenant transaction, bind the actor and load current tenant, subject, membership and role authority.
3. Match the presented certificate to inventory and revalidate its current authoritative status.
4. Evaluate the role/action matrix. An ineligible row is denied without calling OPA.
5. Load the current trust state and active tenant policy bundle, then build the complete immutable policy input from server-controlled values.
6. Validate the OPA result and continue only for the exact outcome `ALLOW`.
7. Recheck request-state freshness, run an explicitly tenant-qualified query and retain forced row-level security as an independent isolation layer.

This ordering means a high score or OPA `ALLOW` cannot repair a revoked certificate, inactive authority, ineligible role or a cross-tenant resource. A stale or missing trust state carries its mandatory `DENY` signal without exposing a usable policy score. `STEP_UP`, `DENY` and `QUARANTINE` are non-allow in T7.2; their later workflows cannot bypass this gate.

## Request context and modes

The API creates request and correlation IDs, request time, method, canonical route template, network-zone placeholder and a SHA-256 resource identifier hash. Dynamic route parameters are represented in lowercase braces, for example `/v1/tenant-records/{recordid}`, matching the contract grammar. Caller headers, query fields and bodies cannot select the mode or supply policy outcomes, identity, tenant, roles, trust, sensitivity or ownership.

Adaptive repository construction requires the branded policy-enforcement service and advertises `adaptive-trust-opa-enforcement-v1`; the API rejects an adaptive repository without that declaration. Baseline construction rejects a policy service so an experiment cannot accidentally mix the two decision paths.

## Verification

Run `npm run policy-enforcement:verify`. The focused tests cover the exact OPA URL and envelope, complete input assembly, response/state binding, network and malformed-response failure, stale high-score denial, all five protected repository operations, revoked-certificate short-circuiting, cross-tenant denial after OPA `ALLOW`, and data-query suppression after `DENY`. `npm run test:api` additionally proves that every registered protected route supplies the immutable policy request context.

T7.2 does not define Rego rules, tenant policy bundles, score thresholds, step-up verification or quarantine execution. Those are separate later tasks.
