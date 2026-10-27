# Tenant trust and decision history dashboard

## Purpose

T10.2 adds an explainable trust view to the local Phase 10 review dashboard. It lets a reviewer follow a subject's current trust score back to its five normalized components, verify whether the state is fresh enough for policy use, identify the immutable trust and policy versions involved, and inspect prior trust transitions and authorization outcomes.

## Tenant and subject scope

The server resolves the selected review persona through the same certificate-derived tenant context used elsewhere in the demo. A tenant member receives only their own trust record. A tenant administrator receives records for subjects in the same tenant. The adapter filters on the trusted tenant ID before it builds explanations; a browser-provided subject identifier cannot widen the response.

This is a deterministic review adapter, not a production history endpoint. A production endpoint must read the existing tenant-bound trust transition, score-lookup and policy-decision provenance stores through constrained service functions. It must not accept tenant, score, role, freshness or policy provenance from a public request.

## Explanation data

`apps/review-demo/trust-dashboard.mjs` uses the implemented repository modules rather than copying their arithmetic or policy schema:

- `calculateWeightedTrustScore` calculates the five weighted contributions with the versioned trust model.
- `initializeTrustControlState` classifies the resulting trust band using the implemented transition thresholds.
- `createSlide14PrototypePolicyData` supplies the validated tenant-bound action rules, score bands and step-up requirements.

The response includes the current last-known score, the policy-usable score, band, observation age, staleness limit, model version, trust configuration version, state update version, policy version, policy bundle version and calibration label. Each component shows its normalized value, configured weight and weighted contribution.

## Freshness and decisions

A score is policy-usable through the exact staleness boundary. Once its age exceeds that boundary, the view retains the last-known score for explanation but returns a null policy score, marks the state stale and records `TRUST_STATE_STALE`. This mirrors the fail-closed trust-score lookup contract.

Decision history shows the action, outcome, reason code, evaluated score and exact policy bundle. The review records cover `ALLOW`, `DENY`, `STEP_UP` and `QUARANTINE` without treating the score as a substitute for certificate, tenant, membership, role or resource checks. The policy defaults remain explicitly unvalidated prototype settings.

## Historical transitions

Transition history is newest first and includes prior/new scores, prior/new bands, a bounded reason, immutable model and configuration versions, observation time and a synthetic transition identifier. The view contains no raw evidence payload, private key, certificate material or unredacted resource identifier.

## Verification

Run:

```text
npm run trust-dashboard:verify
```

The focused tests prove member self-scope, administrator same-tenant scope, exact five-component calculation, model/configuration provenance, the freshness boundary, fail-closed stale behavior, policy reason/version display and ordered historical transitions. Browser verification confirms the rendered view and persona switching.
