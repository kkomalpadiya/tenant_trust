# Internal trust-score lookup and freshness contract

T6.9 exposes the current durable trust transition to internal policy consumers without accepting a tenant, subject, score or version from the caller. The application service requires the existing branded tenant context. Its PostgreSQL repository opens a transaction, assumes the least-privilege application role, binds that exact tenant and actor with `identity.set_tenant_actor_context`, and calls the zero-argument `trust.get_current_actor_trust_score()` function.

PostgreSQL is authoritative for both the current transition and time. The function reads the subject's durable current-transition pointer, joins the exact immutable configuration used by that transition, and calculates age from `statement_timestamp()` and `evaluated_at`. The boundary is inclusive: `ageSeconds <= staleAfterSeconds` is fresh; any greater age is stale.

## Consumer result

Every result is bound to the authenticated tenant and subject and identifies one of three states:

| State | Policy score and band | Last-known score and band | Policy use | Required outcome |
| --- | --- | --- | --- | --- |
| `fresh` | Present | Present and identical | `usableForPolicy: true` | None |
| `stale` | Withheld | Present for audit and diagnosis only | `usableForPolicy: false` | `DENY` with `TRUST_STATE_STALE` |
| `missing` | Absent | Absent | `usableForPolicy: false` | `DENY` with `TRUST_STATE_MISSING` |

A stale score is deliberately not returned in `policyScore`. Its last-known value cannot be mistaken for current policy input. Missing state returns no age, transition, model or configuration metadata.

Fresh and stale results also carry the measured age, freshness limit, transition ID, state-update version, model version, configuration version, observation/evaluation/recording times and explanation SHA-256 digest. Consumers can therefore bind a decision or audit record to the exact durable state without querying trust tables directly.

## Fail-closed boundary

The application role receives execution permission only on the constrained lookup function; it has no direct access to transition or configuration tables. The trust engine does not receive this policy-consumer permission. The service rejects unbranded context, cross-bound tenant/subject results, malformed scores, bands, timestamps, versions and hashes, or a result that claims stale or missing state is usable.

Run `npm run trust-score-lookup:verify`. The gate runs the trust unit suite and a rolled-back PostgreSQL scenario that proves least privilege, exact actor binding, fresh output, the inclusive freshness boundary, stale score withholding with conservative denial, missing-state denial and context clearing. Apply migration `024_internal_trust_score_lookup.sql` with `npm run infra:migrate` before running the gate in another environment.
