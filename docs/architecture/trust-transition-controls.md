# Trust transition controls

T6.6 applies safety controls after deterministic weighting and temporal smoothing. The input score is already a complete 0–100 observation. The output remains a policy input: a band never authorizes a request by itself and cannot rescue an invalid identity, tenant binding or revoked certificate.

## Prototype bands and hysteresis

The initial, uncalibrated prototype has three bands:

| Band | Base score interval | Deterioration threshold | Recovery threshold |
| --- | ---: | ---: | ---: |
| Low | `0 <= score < 40` | Not applicable | `score >= 45` |
| Medium | `40 <= score < 70` | `score < 35` | `score >= 75` |
| High | `70 <= score <= 100` | `score < 65` | Not applicable |

The five-point gaps on each side of a base boundary prevent a score near 40 or 70 from repeatedly changing bands. Deterioration applies immediately and may skip directly from high to low when the controlled score is below 35. Recovery requires two consecutive qualifying evaluations supported by at least two distinct enrolled sources. Each qualifying evaluation can advance only one band. A failed score or corroboration check resets the recovery streak.

These thresholds are deterministic prototype defaults, not calibrated effectiveness claims. T6.7 can place revised values in a new immutable tenant configuration, and T6.10 will exercise calibration fixtures before the defaults support an evaluation claim.

## Bounded source influence

Each accepted evidence receipt snapshots the lower of the tenant-wide and source-specific influence caps. T6.6 interprets that fraction as the largest absolute score movement one ordinary observation may cause:

`maximum score delta = maximum source influence * 100`

For example, a receipt cap of `0.10` allows that observation to move the controlled score by no more than ten points in either direction. The trust service must load this value from the accepted receipt. It must never accept an influence cap from a public request or the metadata-only event. Repeated evidence from one source cannot satisfy the distinct-source recovery rule, which prevents a noisy or compromised source from farming an upward band transition.

## Critical negative evidence

Critical overrides use a closed rule set. Callers cannot supply a score ceiling or invent a positive override.

| Critical kind | Required component | Score ceiling | Forced band |
| --- | --- | ---: | --- |
| `identity-compromised` | Identity | 20 | Low |
| `device-compromised` | Device | 20 | Low |
| `account-takeover-pattern` | Behaviour | 20 | Low |
| `certificate-revoked` | Certificate | 0 | Low |
| `blocking-compliance-breach` | Compliance | 20 | Low |

A matching critical signal may bypass the ordinary source cap only to reduce the score. The result is the lowest of the previous score, candidate score and configured ceiling, so an override can never improve trust. Clearing the critical condition does not restore the prior band. Later recovery still follows the source cap, corroboration, consecutive-evaluation and one-band rules. Certificate validity remains an independent authorization prerequisite even when the trust score is already zero.

The result records the applied cap, requested and applied deltas, recovery qualification, streak, transition reason and any critical rule. T6.8 will include these terms in the durable transition explanation.

Run `npm run trust-controls:verify` for boundary, anti-oscillation, source-farming and critical-override checks.
