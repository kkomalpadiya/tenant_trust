# Adaptive score and resource-sensitivity policy

## Boundary

T7.4 implements the first executable policy for `tenant_trust/authorization/decision`. It consumes only the T7.1 server-built input and returns the existing complete decision contract. A score influences a decision but never replaces certificate, tenant, subject, membership, role, resource or freshness checks.

The initial values reproduce the prototype presentation's slide 14 and are labelled `unvalidated-prototype-defaults`. They are a starting hypothesis for evaluation, not universal security thresholds. Each tenant receives the values inside its versioned `access-control` bundle and can adopt a stricter or differently calibrated version through the T7.3 publication/activation lifecycle.

## Initial score policy

The broad authorization disposition bands are:

| Score | Disposition |
| --- | --- |
| Below 50 | `QUARANTINE` with a separate `restrict-access` obligation |
| 50 to below 65 | Restricted; the action-specific minimum still decides |
| 65 to below 80 | Conditional; sensitive configured actions require step-up |
| 80 to 100 | Trusted; action, sensitivity, role and step-up requirements still apply |

These disposition bands are not the trust engine's `low`/`medium`/`high` labels. OPA uses the numeric current score and separately verifies that the input's current and last-known trust values match.

The initial action rules are:

| Action | Sensitivity | Minimum score | Eligible roles | Step-up |
| --- | --- | ---: | --- | --- |
| `profile:read` | confidential | 55 | member, admin | no |
| `record:read` | confidential | 55 | member, admin | no |
| `record:write` | confidential | 65 | member, admin | no |
| `record:export` | sensitive | 65 | admin | required |
| `tenant:admin` | critical | 80 | admin | required |
| `member:manage` | critical | 80 | admin | required |
| `certificate:manage` | critical | 80 | admin | required |
| `admin-key:rotate` | critical | 90 | admin | required |

Profile read at 55 and administrator key rotation at 90 plus step-up are explicit examples from the presentation. The remaining initial action mappings make the prototype executable and remain subject to calibration.

## Fail-closed order

OPA checks configuration validity, tenant/subject/resource binding, active authoritative certificate state, active tenant authority and fresh usable trust before it considers a score. It then applies quarantine, requires a configured action, verifies exact resource sensitivity and role eligibility, checks the action minimum and finally emits `STEP_UP` or `ALLOW`.

Unknown actions, sensitivity downgrades, role mismatches, scores below the action minimum and invalid configuration return `DENY`. Stale or missing trust preserves its mandatory denial reason and exposes no policy-usable score. A score below 50 returns `QUARANTINE`, but the policy does not mutate tenant, subject or certificate state.

A rule marked `stepUpRequired` returns `STEP_UP` until T7.5's Ed25519 challenge flow supplies a fresh proof that is bound to the tenant, subject, action and session. The API consumes that proof once, in the protected operation's transaction, and OPA independently checks its bindings and maximum age before returning `ALLOW`. T7.6 consumes quarantine obligations through a separate auditable workflow.

## Tenant configuration safety

`createSlide14PrototypePolicyData` builds the initial tenant-scoped document. `validateAdaptiveAuthorizationPolicyData` requires the exact schema, ordered 0–100 bands, one unique rule for every supported action and the trusted tenant ID. Tenant versions cannot downgrade canonical sensitivity, broaden canonical role eligibility or remove a mandatory step-up requirement.

The local root `policies/data.json` contains deterministic Alpha-only development configuration plus deployment provenance. A production distributor must materialize the activated tenant bundle and its exact policy ID, bundle version and digest; the API rejects any decision whose provenance differs from PostgreSQL.

## Verification

Run:

```powershell
npm run adaptive-policy:verify
```

The gate runs policy-service tests, 14 Rego tests (including the readiness policy), one real OPA evaluation validated through the API client and the protected-route enforcement regressions. It also proves OPA's input digest matches the application's canonical SHA-256 digest.
