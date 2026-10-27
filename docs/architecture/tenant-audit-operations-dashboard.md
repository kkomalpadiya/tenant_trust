# Tenant audit verification and operations dashboard

## Purpose

T10.3 adds a review-facing operations view for the durable controls completed in Phases 8 and 9. It makes ledger delivery gaps, causal verification results and security-action failures visible without turning the browser into a privileged audit reader or exposing evidence content.

## Server-owned scope

`apps/review-demo/audit-operations-dashboard.mjs` resolves the selected review persona through the same trusted tenant-context boundary used by the rest of the console. A tenant member receives only records whose subject matches the authenticated subject. A tenant administrator receives records for subjects in the same tenant. Tenant identifiers in the dataset are always filtered on the server before serialization.

The projection uses the repository's actual `AUDIT_OUTBOX_POLICY` and `SECURITY_ACTION_OPERATIONS_POLICY`. This keeps retry limits, stuck-work detection and the rule that audit delivery is required for a healthy action aligned with the production services.

## Operational views

The browser renders three related views:

- Ledger delivery distinguishes `pending`, `committed` and `failed` records, including bounded attempt counts, review-safe transaction references, committed block numbers and scheduled retry times.
- Causal verification distinguishes complete chains from records waiting on delivery and failed chains. Failure reason codes use the verifier vocabulary, including missing causation links and ledger commitment mismatches.
- Security-action operations expose quarantine, severity and governed-recovery work with execution state, operational severity, audit delivery state and retry timing. A failed action or required audit commitment keeps the health result critical.

The existing session request outcomes remain available in a collapsed secondary panel. They are intentionally separate from durable ledger and action health so a successful browser scenario cannot hide a delivery or orchestration failure.

## Data minimization

The review response contains synthetic record, correlation, transaction and action references plus operational state. It does not contain raw evidence, event payloads, canonical commitment preimages, bearer tokens, passwords, certificate private keys or production credentials. The UI states that evidence-content and secret-field counts are zero.

## Verification

Run:

```text
npm run audit-operations-dashboard:verify
```

The focused gate verifies member and administrator scope, cross-tenant exclusion, all three ledger states, causal failure visibility, actionable quarantine retries, imported production policy values, data minimization and JavaScript syntax.
