# Security action state machine

## Boundary

T9.1 defines the closed-loop security-action state machine without executing actions. The model consumes only a contract-valid policy outcome or a separately authorized escalation or recovery command. It returns a deterministic next posture and rejects invalid combinations. T9.3 now supplies persistence, retries and certificate-authority confirmation, while T9.4 records authenticated lifecycle outcomes as non-recursive trust feedback. Session invalidation, governed recovery and action audit delivery remain later Phase 9 tasks.

The state is composite because access, renewal eligibility and certificate validity are different controls. A subject can have restricted access while renewal remains allowed, or normal access while renewal is explicitly blocked. Collapsing these facts into one linear status would lose enforcement information.

| Dimension | States | Meaning |
| --- | --- | --- |
| Access | `normal`, `restricted`, `suspended` | Application authorization posture for the subject |
| Renewal | `allowed`, `blocked` | Whether certificate renewal may proceed |
| Target certificate | `active`, `revoked` | Authoritative state of the certificate named by the action |
| Replacement | `not-required`, `required`, `issued` | Recovery status after permanent revocation |

Suspension always blocks renewal. A revoked certificate requires a replacement and cannot return to `active`. If a replacement is issued, the original target remains `revoked`; the replacement is a distinct certificate with a new identity and lifecycle.

## Policy outcome mapping

| Policy outcome | Immediate durable state action |
| --- | --- |
| `ALLOW` | None. An allow result does not undo an earlier security action. |
| `STEP_UP` | None. The caller must satisfy the bound second-factor flow. |
| `DENY` | None. Denial applies to the request and does not silently mutate subject or certificate state. |
| `QUARANTINE` | Exactly the obligation carried by the validated decision: `restrict-access` or `suspend-subject`. |

The existing OPA contract exposes only the two reversible quarantine obligations. The state machine therefore never infers `block-renewal`, `revoke-certificate`, `restore-access` or `issue-replacement-certificate` from an authorization outcome alone. The [T9.2 trigger and recovery rules](security-action-trigger-recovery-rules.md) separately require fresh independent severe evidence for revocation and completed corroborated trust recovery for recovery eligibility. T9.6 will authenticate recovery actors and execute that workflow.

## Actions and transitions

| Action | Authority class | Effect | Reversible |
| --- | --- | --- | --- |
| `restrict-access` | Validated `QUARANTINE` obligation | Set access to `restricted`; preserve renewal and certificate state | Yes |
| `suspend-subject` | Validated `QUARANTINE` obligation | Set access to `suspended` and renewal to `blocked` | Yes |
| `block-renewal` | Severity rule | Set renewal to `blocked`; preserve access and certificate state | Yes |
| `revoke-certificate` | Severity rule | Suspend access, block renewal, permanently revoke the target and require a replacement | No |
| `restore-access` | Recovery authorization | Return access to `normal` and renewal to `allowed`; never change certificate state | Yes |
| `issue-replacement-certificate` | Recovery authorization | Mark a distinct replacement issued while the target remains revoked | No; the new certificate has its own lifecycle |

Repeated application of the same action is idempotent. A stronger existing control dominates a weaker one: restricting an already suspended subject does not reduce the suspension. Recovery of restriction, suspension or a standalone renewal block can use `restore-access`. Recovery after revocation must first issue a replacement; `restore-access` fails closed while replacement remains required.

## Safety invariants

- Only the validated `QUARANTINE` obligation maps directly to a state action. The caller cannot substitute another action type.
- `ALLOW` is not recovery. Trust improvement or a successful request cannot silently clear a prior restriction.
- Suspension implies renewal blocking so a suspended subject cannot bypass the control by rotating a certificate.
- Revocation is irreversible for the target certificate. Neither `restore-access` nor replacement issuance changes it back to active.
- Replacement issuance is allowed only after revocation and does not itself restore application access.
- Unknown actions, incomplete state, impossible state combinations and recovery before replacement fail closed.
- The state machine assigns authority classes. T9.2 now defines severity, corroboration and recovery eligibility; operator roles and governed execution remain T9.6.

## Executable contract

`services/orchestrator/src/index.mjs` exports the stable outcomes, action catalog, policy mapping, composite-state validator and pure transition function. T9.3 applies that function through the [durable idempotent orchestrator](idempotent-security-action-orchestration.md). `npm run security-action-state-machine:verify` runs unit tests plus an independent gate that checks the model against the shared OPA and action-event schemas and exercises reversible and irreversible paths.
