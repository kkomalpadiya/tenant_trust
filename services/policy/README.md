# Tenant policy service

`@tenant-trust/policy` owns the tenant policy-bundle publication, activation, history and active-version lookup boundaries.

`createPolicyBundleManagementService` accepts only an authoritative tenant-administrator context. It normalizes bounded Rego v1 modules and JSON data, requires the fixed `tenant_trust/authorization/decision` entrypoint, invokes a branded OPA compiler adapter, injects tenant and server-generated policy identity, and hashes canonical bundle JSON. Callers cannot supply tenant, publisher, policy-version ID, hash, validation receipt or lifecycle state.

For the `access-control` policy, publication additionally validates the complete adaptive policy data shape. The data must name the trusted tenant, contain one unique rule for every canonical action, preserve the canonical resource sensitivity, avoid broader roles, retain mandatory step-up requirements and mark thresholds as `unvalidated-prototype-defaults`. `createSlide14PrototypePolicyData` produces the documented initial tenant configuration; later tenant versions may use different ordered score boundaries and stricter rules.

`createPostgresPolicyBundleRepository` calls only constrained PostgreSQL functions. Publication must use the next bundle number for that tenant and policy name. Activation locks the tenant/policy stream, marks the previous active version superseded and selects the validated target in one transaction. Version content and lifecycle events are append-only. Legacy T2.7 metadata remains historical and cannot become active because it has no validated bundle document.

`createPolicyBundleLookupService` returns the single active bundle for the trusted actor tenant. The API enforcement service compares every OPA result with this bundle's policy ID, version, SHA-256 digest and entrypoint. A missing bundle or deployment skew fails closed; the database does not silently accept the version reported by OPA.

Run `npm run policy-bundles:verify` after `npm run infra:migrate`. The gate runs service tests, uses the pinned OPA image to accept valid Rego v1 and reject invalid syntax, exercises the rolled-back PostgreSQL lifecycle and reruns protected-route policy enforcement.

Run `npm run adaptive-policy:verify` to test the configuration validator, exact Rego score boundaries, real OPA output contract and canonical input digest. See `docs/architecture/adaptive-authorization-policy.md`.
