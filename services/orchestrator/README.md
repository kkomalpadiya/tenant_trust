# Security action orchestration

`@tenant-trust/orchestrator` owns the closed-loop security-action boundary. T9.1 defines the executable state machine, and T9.2 defines trigger severity, independent corroboration and recovery eligibility.

Only a contract-valid `QUARANTINE` decision with an explicit `restrict-access` or `suspend-subject` obligation maps directly to reversible containment. `ALLOW`, `STEP_UP` and `DENY` do not mutate durable security state. One fresh severe signal can block renewal, while revocation requires two sources, two actionable critical kinds and a matching low-band T6.6 critical transition. Score movement alone can never revoke.

Recovery reuses the T6.6 two-source/two-evaluation controls. Restricted access needs a recovered medium band at score 45; suspension, renewal blocking and replacement after revocation need a recovered high band at score 75. Active severe evidence blocks recovery, and revocation recovery requires the cause to be resolved. Eligibility never substitutes for the explicit `recovery-authorization` that T9.6 will enforce.

The model keeps access, renewal and certificate posture separate. Restriction, suspension and renewal blocking are reversible. Revocation permanently leaves the target certificate revoked. Recovery from revocation first issues a distinct replacement certificate and may then restore subject access; it never reactivates the revoked certificate.

This task does not persist actions, call a certificate authority, invalidate sessions, feed outcomes into trust or deliver audit commitments. Those effects belong to T9.3 through T9.9.

Run `npm run security-action-state-machine:verify` for T9.1 and `npm run security-action-rules:verify` for the T9.2 unit and independent gates.
