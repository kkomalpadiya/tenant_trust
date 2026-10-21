# Policy decision provenance

Every contract-valid adaptive OPA decision is recorded as one canonical, append-only provenance document before its outcome can affect a protected operation. The record is the durable link between the server request, authenticated identity and certificate, authoritative trust state, exact active policy bundle, policy input and returned result. It is deliberately separate from the smaller request-outcome audit stream and from quarantine action requests.

## Canonical record

`createPolicyDecisionProvenance` builds the `tenant-trust-authorization-decision-provenance-json-v1` document only after the OPA response has passed the existing contract and state-binding checks. Lexicographically sorted JSON is hashed with SHA-256. The document contains:

- the server request and correlation IDs, request time, method, route and network context;
- tenant, subject, role, action, sensitivity, certificate and membership versions;
- SHA-256 hashes of the resource context and optional step-up context rather than their raw identifiers or proof material;
- the decision ID, outcome, reasons, obligations and evaluation time;
- the trust transition, update, model and configuration versions plus the trust explanation digest;
- the active policy ID, version, bundle version, bundle digest and OPA path; and
- the policy input contract and canonical input digest.

The trust transition is a tenant-qualified foreign key to the durable transition explanation created by the trust engine. Its explanation digest binds the decision to that transition's evidence-derived explanation and contributions without copying raw evidence into the audit row. The policy version is likewise tenant-qualified and must match the exact active bundle metadata returned by OPA.

## Persistence and outcome semantics

Migration `029_policy_decision_provenance.sql` creates `audit.policy_decision_provenance` and the constrained `audit.record_policy_decision_provenance` writer. The application role has execute permission on the writer but no direct table access. The writer derives tenant and actor from transaction-local context, recomputes the canonical SHA-256 digest, validates every database-backed version and relationship, and permits only an exact idempotent replay. Rows cannot be updated or deleted.

The persistence boundary is outcome-specific:

- `ALLOW` records provenance in the same transaction as the protected query.
- `DENY` and `STEP_UP` commit only the valid decision provenance, then return the existing generic denial without running the protected query or creating a security action.
- `QUARANTINE` commits the decision provenance and its correlated action request together, while the protected query does not run.
- If a valid decision cannot be recorded, the transaction rolls back and the operation fails closed.

OPA transport failures, malformed output and state-binding failures are not policy decisions, so they cannot produce a valid decision-provenance document. The sanitized request-outcome audit continues to capture those dependency failures and their server correlation IDs.

## Verification and ledger boundary

Run the task gate after applying migrations:

```text
npm run policy-provenance:verify
```

The gate runs the API tests and a rolled-back PostgreSQL fixture that checks exact request, result, trust/explanation, policy and input bindings; server-side digest verification; exact-replay idempotency; conflicting replay rejection; cross-tenant rejection; least privilege; and append-only enforcement.

This task creates the stable off-chain bytes and digest required for later verification. It does not claim that the digest has been submitted to or committed by Hyperledger Fabric; that remains a later audit phase.
