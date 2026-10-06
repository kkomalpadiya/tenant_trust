# Normalized trust components and initial weights

## Boundary

T6.1 defines the input contract for the adaptive trust engine. A normalized component vector contains exactly five finite values on a common inclusive 0–100 scale. Zero is the least trusted posture and 100 is the most trusted posture. The scale is not a probability, an authorization decision or proof that an evidence claim is true.

This task does not map raw evidence into component values or calculate a weighted score. Those explainable normalization and calculation rules belong to the later deterministic scoring task. Temporal smoothing, cold start, persistence, source influence, hysteresis and policy enforcement also remain outside this contract.

## Components

| Component | Evidence represented | Initial weight |
| --- | --- | ---: |
| Identity | Authentication assurance and authoritative identity state | 0.20 |
| Device | Managed-device posture and device risk | 0.25 |
| Behaviour | Observed activity and behaviour risk | 0.25 |
| Certificate | Authoritative certificate lifecycle and status | 0.15 |
| Compliance | Evaluated control and compliance posture | 0.15 |

The weights are the slide 13 starting values and sum to 1. They are design defaults, not calibrated effectiveness claims. The `1.0.0` default is immutable so historical calculations can name the model that produced them.

## Validation and tuning rules

- All five components are required exactly once. Missing evidence remains missing; callers cannot silently replace it with zero or a safe default.
- Every normalized component must be a finite number from 0 through 100. Strings, `NaN`, infinities and extra component names are invalid.
- Every weight must be a finite number from 0 through 1, all five weights must be present, and their total must be 1.
- A tenant-tuned configuration receives its own semantic model version and produces a new immutable value. It never mutates the initial defaults. Activation, history and rollback are implemented by the later versioned-configuration task using the existing tenant-scoped `trust.trust_configurations` storage boundary.
- Certificate score is explanatory trust input only. An invalid, expired, revoked, unknown or foreign-tenant certificate still denies authentication regardless of any component or aggregate score.

## Executable contract

`packages/trust-model/src/index.mjs` exports the stable component order, definitions, normalized range, initial configuration and fail-closed validators. It deliberately exposes no score-calculation function. `npm run trust-model:verify` runs focused unit tests and an independent contract gate for the canonical defaults, boundary values, tunable alternatives and invalid inputs.
