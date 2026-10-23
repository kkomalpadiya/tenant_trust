# Complete security feedback-loop verification

## Purpose

T9.10 closes Phase 9 with one fail-fast command that verifies the implemented feedback loop across its real subsystem boundaries. It does not introduce a second model or claim that the prototype thresholds detect real attacks. Instead, it composes the already versioned Phase 7 and Phase 9 gates in causal order so a regression at any boundary fails the overall result.

## Verified path

The gate proves the following connected behavior:

1. New account-takeover behavior evidence changes the explainable trust transition from score 69 to a low-band critical override at score 20.
2. OPA reevaluates the same active certificate and changes a sensitive export from `ALLOW` to `QUARANTINE`, preserving decision provenance and the exact trust-transition binding.
3. The security-action rules allow only justified containment: policy quarantine is reversible, while permanent revocation additionally requires two fresh sources, two critical kinds and a matching critical trust transition.
4. Authorized actions retain stable IDs across retries, update versioned security state once and invalidate tenant-and-subject-scoped sessions and caches.
5. Authenticated certificate lifecycle outcomes create one causal trust effect and are explicitly ineligible to trigger another action, preventing recursive escalation.
6. Action and governed-recovery events are captured as immutable audit expectations, projected through the Fabric commitment outbox and exposed to causal verification.
7. Recovery requires current recovered trust, no active severe evidence, an administrator's bound single-use step-up proof and the exact security-state version. Revocation remains permanent; recovery uses a distinct replacement certificate before restoring access.
8. Replay, oscillation, competing recovery, expired leases and missing or failed audit delivery remain visible and fail closed.

Each database verifier runs inside a transaction and rolls back its fixtures. The gate may apply pending migrations to the configured local database, but it does not retain scenario records.

## Run the gate

Start the normal local dependencies, then run:

```powershell
npm run security-feedback-loop:verify
```

The command runs the adaptive authorization scenario and all Phase 9 execution, feedback, recovery, audit, adversarial and operations gates in order. It stops at the first failure and prints the responsible boundary.

The final pass is an implementation-verification result only. The trust weights, thresholds and deterministic risky-evidence fixture remain `UNVALIDATED_PROTOTYPE_DEFAULTS`; the command makes no production detection-effectiveness claim.
