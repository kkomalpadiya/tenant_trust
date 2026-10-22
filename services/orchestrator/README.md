# Security action orchestration

`@tenant-trust/orchestrator` owns the closed-loop security-action boundary. T9.1 defines an executable state machine for access restriction, subject suspension, renewal blocking, permanent certificate revocation and governed recovery.

Only a contract-valid `QUARANTINE` decision with an explicit `restrict-access` or `suspend-subject` obligation maps directly to a state action. `ALLOW`, `STEP_UP` and `DENY` do not mutate durable security state. Renewal blocking and certificate revocation require the separate severity and corroboration rules planned for T9.2. An `ALLOW` result never restores access automatically; recovery actions require the governed authorization planned for T9.6.

The model keeps access, renewal and certificate posture separate. Restriction, suspension and renewal blocking are reversible. Revocation permanently leaves the target certificate revoked. Recovery from revocation first issues a distinct replacement certificate and may then restore subject access; it never reactivates the revoked certificate.

This task does not persist actions, call a certificate authority, invalidate sessions, feed outcomes into trust or deliver audit commitments. Those effects belong to T9.3 through T9.9.

Run `npm run security-action-state-machine:verify` from the repository root for the focused unit and independent contract gate.
