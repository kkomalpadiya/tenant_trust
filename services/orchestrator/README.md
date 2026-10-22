# Security action orchestration

`@tenant-trust/orchestrator` owns the closed-loop security-action boundary. T9.1 defines the executable state machine, and T9.2 defines trigger severity, independent corroboration and recovery eligibility.

Only a contract-valid `QUARANTINE` decision with an explicit `restrict-access` or `suspend-subject` obligation maps directly to reversible containment. `ALLOW`, `STEP_UP` and `DENY` do not mutate durable security state. One fresh severe signal can block renewal, while revocation requires two sources, two actionable critical kinds and a matching low-band T6.6 critical transition. Score movement alone can never revoke.

Recovery reuses the T6.6 two-source/two-evaluation controls. Restricted access needs a recovered medium band at score 45; suspension, renewal blocking and replacement after revocation need a recovered high band at score 75. Active severe evidence blocks recovery, and revocation recovery requires the cause to be resolved. Eligibility never substitutes for the explicit `recovery-authorization` that T9.6 will enforce.

The model keeps access, renewal and certificate posture separate. Restriction, suspension and renewal blocking are reversible. Revocation permanently leaves the target certificate revoked. Recovery from revocation first issues a distinct replacement certificate and may then restore subject access; it never reactivates the revoked certificate.

T9.3 now persists authorized actions, claims them with expiring leases, retries failures under the same stable action ID, and stores attempt plus terminal state. Reversible database controls complete atomically; certificate revocation requires an injected T3.7 executor and exact issuer confirmation before the database accepts success. Recovery execution remains reserved for T9.6, while session invalidation, trust feedback and audit delivery remain later tasks.

Run `npm run security-action-state-machine:verify` for T9.1, `npm run security-action-rules:verify` for T9.2 and `npm run security-action-orchestration:verify` for the T9.3 unit and PostgreSQL gates.
