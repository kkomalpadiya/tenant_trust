# Security-action adversarial verification

T9.8 exercises the closed-loop action path under oscillation, replay, conflicting work and a compromised evidence source. The gate composes the implemented T9.2–T9.6 boundaries instead of treating their unit guarantees as independent claims.

## Conflict safeguards

Migration `040_security_action_conflict_safeguards.sql` keeps a recovery authorization bound to one trust transition and one security-state version. The state row serializes authorization. A second request for the same target, checkpoint, version and action fails with `RECOVERY_ALREADY_AUTHORIZED` before retaining an action or consuming its step-up proof.

The worker claim boundary performs two fail-closed checks before an external executor runs:

- a recovery authorization whose state version is stale becomes a visible, non-retryable `RECOVERY_STATE_CHANGED` attempt;
- a new restriction, suspension, renewal block or revocation that is already represented by durable state becomes a visible, non-retryable `ACTION_ALREADY_SATISFIED` attempt.

Pending or retryable severity work takes precedence over recovery for the same tenant, subject and certificate. The one-executing-action constraint and optimistic state version still protect completion if state changes after claim.

## Adversarial scenarios

`npm run security-action-adversarial:verify` covers:

- repeated low/high trust movement without automatic restoration or progressive escalation;
- multiple severe statements from one source, including different critical kinds, without revocation authority;
- active severe evidence blocking an otherwise qualifying recovery checkpoint;
- repeated revocation remaining a no-op at the state boundary;
- terminal certificate feedback remaining ineligible to trigger another security action;
- stable action retries and suppression of a new already-satisfied trigger;
- exact lifecycle-event and Redis invalidation redelivery applying no second effect;
- exact recovery replay returning one authorization, a competing authorization being rejected, and stale recovery failing before execution.

Database fixtures run in transactions and roll back. The live Redis invalidation gate removes its test keys.

## Boundary

These tests establish deterministic control behavior, not the effectiveness of prototype trust weights or thresholds. Operational alerting and restart handling for terminally suppressed, failed or stuck work belong to T9.9.
