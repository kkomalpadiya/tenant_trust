# Adaptive policy matrix verification

## Purpose

T7.8 turns the adaptive authorization rules into one auditable decision matrix. The checked-in fixture records the tenant policy profile, action, score, roles, resource sensitivity, step-up state and expected outcome for every case. The verifier rejects a matrix that omits a required category or any supported action before it invokes OPA.

This is verification of the existing policy boundary, not a change to authorization behavior or a claim that the prototype thresholds are production-calibrated.

## Coverage

`tests/fixtures/policy/adaptive-policy-matrix-v1.json` covers:

- all eight configured actions;
- exact boundaries at 50, 55, 65, 80, 90 and 100 plus fractional values immediately below or above relevant boundaries;
- tenant-member and tenant-admin eligibility;
- confidential, sensitive and critical resource rules, including sensitivity mismatches;
- an Alpha default profile and a valid stricter Beta profile;
- absent, valid and expired step-up proofs.

The paired tenant cases intentionally hold request conditions constant while changing the tenant configuration. At score 57, Alpha allows `profile:read` while Beta denies it because Beta raises the minimum to 60. At score 60, Alpha allows `record:read` while Beta returns `STEP_UP` because Beta marks that action as step-up protected.

## Verification boundary

`scripts/verify-policy-matrix.mjs` validates the fixture shape and category coverage, builds each tenant configuration through `validateAdaptiveAuthorizationPolicyData`, and evaluates all cases through the real `tenant_trust/authorization/decision` Rego entrypoint in the pinned OPA container. It then validates every returned decision through the API client and asserts the request hash, tenant, subject, trust-state and obligation bindings.

Run:

```powershell
npm run policy-matrix:verify
```

The command first runs the policy-service tests and checked-in Rego suite, then runs the fixture-driven matrix. It requires Docker and the repository `.env` file, but it does not require running services or write persistent infrastructure state.
