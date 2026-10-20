# OPA decision contract

## Boundary

T7.1 defines the versioned data exchanged between the API policy enforcement point and OPA. T7.2 connects protected routes to that contract, T7.3 versions tenant bundles and T7.4 supplies the first executable score/sensitivity rules. T7.5 adds bound step-up proof acceptance, and T7.6 turns quarantine outcomes into durable action requests while keeping protected access denied. Executing those action requests remains later orchestration work.

The canonical JSON Schemas are:

- `packages/contracts/schemas/policy/opa-decision-input.schema.json`
- `packages/contracts/schemas/policy/opa-decision-output.schema.json`

Both contracts use schema version `1.0.0`. The OPA Data API decision path is `tenant_trust/authorization/decision`. Unknown fields and unknown actions or outcomes are rejected.

## Trusted input

The application assembles policy input only from validated server-side state. HTTP headers, path values, request bodies and other caller data cannot supply or replace the identity, tenant, roles, resource ownership, sensitivity, certificate status, trust score or policy version.

| Section | Required content | Authority |
| --- | --- | --- |
| `identity` | mTLS authentication ID, tenant and subject IDs, certificate and issuer IDs, fingerprint, canonical serial, current certificate state, status source/version and freshness times | Gateway identity plus authoritative certificate-status validation |
| `tenantContext` | tenant and subject IDs, normalized tenant roles, active/suspended lifecycle states and tenant/subject/membership versions | Trusted tenant-context resolver and PostgreSQL |
| `action` | One canonical operation identifier | Server route mapping |
| `resource` | tenant ID, bounded type, hashed identifier, sensitivity, eligible scope and owner subject when applicable | Tenant-scoped repository and role-action matrix |
| `trust` | fresh, stale or missing state with exact transition/configuration provenance | Internal trust-score lookup |
| `requestContext` | request/correlation IDs, UTC request time, HTTP method, route template, network zone and any action-bound step-up proof | Server request lifecycle and step-up verifier |

`identity.valid` records the certificate verdict; it is not a caller assertion. A false verdict remains representable so policy and enforcement can produce a reasoned non-allow outcome. A true verdict requires active authoritative status, a positive status version and bounded freshness times.

Tenant, subject and action values appear in more than one section so policy can verify their binding. The input builder and Rego policy reject mismatches before authorization. A high trust score never repairs an invalid certificate, inactive tenant/subject/membership, missing role, cross-tenant resource or mismatched step-up proof.

## Trust freshness

The trust part follows the T6.9 lookup contract:

- `fresh` is the only state with `usableForPolicy: true` and a `policyScore`/`policyBand`.
- `stale` withholds the policy score, retains last-known values only for explanation, and requires `DENY` with `TRUST_STATE_STALE`.
- `missing` contains no score/version/timestamp provenance and requires `DENY` with `TRUST_STATE_MISSING`.

The schema enforces each state shape. The input builder and policy must also verify equal tenant/subject bindings, equal fresh and last-known scores/bands, chronological timestamps and the inclusive freshness boundary `ageSeconds <= staleAfterSeconds`.

## Outcomes

OPA returns one complete object with exactly one of four outcomes:

| Outcome | Meaning | Required obligation |
| --- | --- | --- |
| `ALLOW` | All required identity, tenant, role, resource, trust and contextual controls passed | None |
| `STEP_UP` | Access is not yet allowed; a second factor bound to tenant, subject, action and session is required | Step-up obligation with a bounded maximum age |
| `DENY` | The request is refused and must not perform the protected operation | None |
| `QUARANTINE` | The request is refused and a separate restricted-access or subject-suspension action must be requested | Quarantine obligation |

`STEP_UP` is not an allow. A successful challenge requires a new decision using a valid, fresh, single-use proof. `QUARANTINE` does not directly mutate certificate or subject state; it instructs the enforcement/orchestration boundary to request a separate auditable action.

Every output identifies the request, correlation, tenant, subject, exact policy bundle, canonical input hash, certificate/authority/trust state versions, decision time and bounded reason codes. The enforcement point must validate the response schema and verify that echoed identifiers and versions match the request input before acting. A malformed, partial, mismatched or unavailable OPA response fails closed.

## Verification

Run:

```powershell
npm run policy-contract:verify
```

The focused contract tests compile both schemas, accept complete representative input, exercise fresh/stale/missing trust, prove invalid certificate state cannot masquerade as valid, reject incomplete and attacker-shaped fields, validate all four outcomes, enforce outcome-specific obligations and require decision provenance. Protected-route enforcement is described separately in [OPA policy enforcement](opa-policy-enforcement.md).
