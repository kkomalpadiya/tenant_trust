# Security action trigger severity and recovery rules

## Boundary

T9.2 defines the pure decision rules that sit between validated trust/policy inputs and the T9.1 security-action state machine. The rules select candidate actions; they do not persist, execute or authorize them. T9.3 will provide durable idempotent orchestration, and T9.6 will authenticate the recovery actor and execute the governed recovery workflow.

Inputs must come from trusted internal records: a schema-valid policy decision, the persisted T6.6 trust transition, and accepted evidence receipts already bound to the same tenant and subject. Public callers cannot declare evidence accepted, choose a severity or supply a score ceiling.

## Trigger levels

| Condition | Severity | Candidate action | Permanent? |
| --- | --- | --- | --- |
| `ALLOW`, `STEP_UP` or `DENY` with no severe signal | None | None | No |
| Valid `QUARANTINE` obligation | Low trust | Exact `restrict-access` or `suspend-subject` obligation | No |
| One fresh actionable severe signal, or incomplete corroboration | Severe pending corroboration | `block-renewal`, plus any existing quarantine containment | No |
| Fresh independent severe evidence with a matching low-band critical trust transition | Severe corroborated | `revoke-certificate` | Yes |

The policy decision remains authoritative for request containment. A trust score—even a score of zero—cannot by itself authorize certificate revocation. A small score decrease can therefore produce a reversible restriction only when the validated policy returns `QUARANTINE`; it cannot be promoted into a permanent certificate action by this boundary.

## Actionable severe evidence

The actionable set is derived from the closed T6.6 critical-evidence rules:

| Critical kind | Required component | T6.6 score ceiling |
| --- | --- | ---: |
| `identity-compromised` | `identity` | 20 |
| `device-compromised` | `device` | 20 |
| `account-takeover-pattern` | `behaviour` | 20 |
| `blocking-compliance-breach` | `compliance` | 20 |

`certificate-revoked` is deliberately a terminal, non-trigger fact. It describes a certificate action that has already happened; treating it as a new revocation trigger would create a self-amplifying feedback loop.

Every severe item must have a unique evidence ID, an enrolled source ID, an exact tenant/subject match, the component required by its critical kind and an observation time no more than five minutes before evaluation. Unknown kinds, mismatched components, cross-target items, future observations, stale observations and duplicate evidence IDs fail closed.

Permanent revocation requires all of the following:

1. At least two distinct source IDs.
2. At least two distinct actionable critical kinds. Repetition by one source or repetition of one conclusion is not independent corroboration.
3. A current T6.6 `critical-override` transition in the low band.
4. The transition's critical kind appears in the corroborating set and its score is at or below that rule's closed score ceiling.

If any revocation condition is missing, the most severe evidence-driven action is the reversible `block-renewal`. A `suspend-subject` quarantine obligation already blocks renewal, so the rule does not emit a redundant second action.

## Recovery eligibility

Recovery eligibility is separate from recovery authorization. Every eligible result still names the `recovery-authorization` authority class, which T9.6 must enforce before any action executes. An `ALLOW` policy result never restores durable state.

The recovery checkpoint is derived from persisted T6.6 transition history. It must record a completed `recovered` transition, at least two consecutive qualifying evaluations and at least two distinct enrolled sources. Active severe evidence blocks every recovery path.

| Current posture | Minimum recovered trust | Additional condition | Next eligible action |
| --- | --- | --- | --- |
| Restricted access | Medium band and score 45 | No active severe evidence | `restore-access` |
| Suspended access or blocked renewal | High band and score 75 | No active severe evidence | `restore-access` |
| Revoked target, replacement required | High band and score 75 | Severe cause resolved; no active severe evidence | `issue-replacement-certificate` |
| Revoked target, replacement issued, access still suspended | High band and score 75 | Severe cause resolved; no active severe evidence | `restore-access` |

The values 45, 75, two sources and two evaluations are imported from the T6.6 default transition configuration instead of being copied into a second independent policy. Future tenant-configured values must be carried in the persisted checkpoint used by the implementation.

Revocation is never reversed. Recovery issues a distinct certificate and leaves the target certificate `revoked`; only access and renewal posture can be restored afterward.

## Scope and verification

`services/orchestrator/src/index.mjs` exports immutable trigger/recovery policies and pure evaluators. The evaluators return candidate action types, corroboration details and stable reason codes. They do not call the CA, write state, invalidate sessions, ingest feedback evidence or submit audit commitments.

Run `npm run security-action-rules:verify` for the orchestrator unit suite and the independent T9.2 gate. The gate proves that score-only deterioration cannot revoke, corroborated severe evidence can authorize revocation, recovery inherits T6.6 safeguards and a revoked target can recover only through replacement.
