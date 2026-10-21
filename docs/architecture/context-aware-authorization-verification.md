# Context-aware authorization verification

T7.10 closes the context-aware authorization phase with one deterministic scenario and one fail-fast phase gate. The scenario demonstrates the intended adaptive behavior: a currently valid certificate receives normal access while trust is usable, then newly accepted risky behavior changes the explainable trust state and restricts a sensitive operation without changing certificate identity.

## Scenario

The versioned fixture `tests/fixtures/policy/adaptive-authorization-scenario-v1.json` is explicitly labelled `UNVALIDATED_PROTOTYPE_DEFAULTS` with `effectivenessClaim: false`. It provides two complete five-component trust snapshots for the Tenant Alpha administrator:

1. The baseline snapshot has five component values of 90. The real weighted-score, temporal-smoothing and transition-control implementations produce trust 69 in the medium band. The valid active certificate receives `ALLOW` for profile access and, with a fresh single-use step-up proof, `ALLOW` for sensitive record export.
2. A newer behavior evidence reference replaces the baseline behavior reference and reports an account-takeover pattern. The explanation records the new evidence ID, its zero normalized behavior value, the weighted contribution, temporal calculation and critical override. The critical rule reduces the controlled score to 20 in the low band.
3. The same active certificate presents a different valid step-up proof for the same sensitive export. The checked-in Rego policy returns `QUARANTINE` with `TRUST_SCORE_QUARANTINE` and the `restrict-access` obligation. The result is therefore caused by the new trust transition rather than certificate invalidity, role ineligibility or proof replay.

The verifier evaluates all three requests through the pinned OPA image and validates each result through the API decision contract. It also builds the canonical T7.9 provenance document and proves that the decision is bound to the exact trust transition, explanation digest, policy bundle and input digest. Raw evidence identifiers stay in the trust explanation and are not copied into decision provenance.

Run the focused scenario with:

```text
npm run adaptive-authorization-scenario:verify
```

This focused command requires Docker and `.env`, but does not require running services or retain state.

## Complete Phase 7 gate

Run:

```text
npm run context-aware-authorization:verify
```

The command stops at the first failure and covers the decision contract, policy bundle lifecycle, adaptive score and sensitivity rules, bound step-up authentication, DENY/QUARANTINE enforcement, outage and freshness behavior, the complete decision matrix, durable decision provenance and the final adaptive scenario. Local services must be running, the demo must be provisioned and migrations through `029_policy_decision_provenance.sql` must be applied because several component gates use rolled-back PostgreSQL fixtures.

`--scenario-only` is available for focused diagnosis. It does not replace the complete gate required to treat Phase 7 as verified.

## Claim boundary

Passing the gate proves that the implemented identity, trust, request, policy and provenance rules compose deterministically at their declared boundaries. It does not establish real-world account-takeover detection accuracy, false-restriction rates or statistically justified trust weights and policy thresholds. Those remain evaluation work.
