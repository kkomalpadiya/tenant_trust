# Adaptive trust-engine verification and calibration fixtures

T6.10 closes Phase 6 with one fail-fast verification gate and a versioned deterministic fixture catalog. The gate proves that the implemented trust pipeline behaves consistently at its declared safety boundaries. It does not claim that the initial weights, thresholds or decay settings are statistically calibrated or effective in production.

## Fixture contract

`test/fixtures/trust-engine-calibration-v1.json` is labelled `UNVALIDATED_PROTOTYPE_DEFAULTS`, `deterministic-regression-only` and `effectivenessClaim: false`. The labels are asserted by the test suite so later edits cannot silently turn a reproducible design fixture into an evaluation claim.

The fixtures cover:

| Risk or boundary | Deterministic expectation |
| --- | --- |
| Normalized score limits | All-zero inputs produce 0, all-100 inputs produce 100, and the published default weights match an independent hand calculation. |
| Freshness boundary | An observation at exactly `staleAfterSeconds` remains fresh. |
| Missing and stale signals | Missing state holds only within the valid window; stale observations are withheld and expired state decays toward the conservative baseline. |
| Band boundaries and recovery | Decimal boundary values map to the declared bands; recovery requires two corroborating sources and two consecutive qualifying evaluations, then advances one band. |
| Replay | Reused event, nonce and sequence identities are rejected without advancing the high-water mark. |
| Flooding | The bounded number of events is accepted, excess events are rate-limited, repeated excess suspends only that source, and the lower effective influence cap is retained. |
| Tenant isolation | Identical event/source/key identifiers are independently scoped by tenant; the live database gates also prove actor-bound state and lookup isolation. |

## Phase gate

Run `npm run trust-engine:verify`. It runs the complete repository test suite, including the fixture catalog, then stops at the first failure across the model contract, weighted score, temporal behavior, transition controls, evidence replay/flood safeguards, tenant-scoped state, configuration lifecycle, validated-evidence consumption, transition explanations and current-score lookup.

The database scenarios run inside transactions and roll back their synthetic changes. Local infrastructure must be running and migrations through `024_internal_trust_score_lookup.sql` must be applied. `--skip-repository-tests` is available for focused diagnosis; it still runs the calibration fixtures but does not replace the full gate required for task completion.

## Calibration limitation

Passing this gate proves deterministic implementation behavior against designed fixtures. It does not establish detection accuracy, false-allow or false-restriction rates, appropriate weights for real tenants, or statistically justified decision thresholds. Those claims require labelled evaluation data and the later comparative evaluation phase. Any revised configuration must receive a new immutable version and be retested without rewriting the `1.0.0` defaults.
