# Causal audit verification

T8.8 verifies an audit trail from the authoritative off-chain records outward. Fabric proves that selected record bytes were committed; it does not by itself prove that the records form a meaningful security history. The verifier therefore accepts one exact tenant and correlation, independently recomputes every canonical commitment, reads the corresponding value from the tenant's Fabric channel, and validates the cross-record links before returning a positive report.

## Verification boundary

The PostgreSQL role `tenant_trust_audit_verifier` has no direct access to the audit outbox, trust-transition contributions or evidence outbox. Two security-definer functions expose only:

- committed-event source material and durable Fabric confirmation metadata for one tenant and correlation;
- accepted evidence identities and delivery-event anchors attached to the trust transitions in that same bundle.

The verifier rejects pending, submitted, failed or otherwise unconfirmed rows. A usable record must retain a successful Fabric validation code, transaction ID and block number. This prevents a locally enqueued value from being reported as ledger evidence.

## Commitment recomputation

For every selected event, the service reruns the canonical T8.3 commitment algorithm from the off-chain event and channel name. The recomputed canonical preimage, ledger key and minimal ledger value must exactly match the durable outbox copy. The verifier then queries Fabric using only the record class and opaque event-key hash and requires the returned value to match the recomputation. A changed event, preimage, stored digest or ledger digest fails closed with a stable reason code.

## Causal graph checks

A successful report requires all of these links:

1. Each trust transition's evidence IDs exactly equal its durable contribution anchors, belong to the same subject and include the immediate evidence event named by the transition's causation ID.
2. Each decision names one trust transition for the same subject and exact score, and that transition cannot occur after the decision.
3. Each decision names an active policy version committed no later than the decision.
4. Each decision names an active certificate for the same subject committed no later than the decision.
5. Each policy/severity action names the exact decision as both its decision reference and immediate cause. Governed recovery instead names the exact recovered trust transition and authorization metadata. Terminal action events name the requested action event, and successful revocation or replacement names the exact certificate lifecycle event.

T9.7 adds an authoritative expectation set alongside correlation lookup. The action verifier starts from immutable database-captured lifecycle points rather than only the records that happen to exist in the audit outbox. It therefore rejects a missing action commitment, altered governance metadata, a broken requested-to-terminal link or a mismatched certificate outcome. See [Security-action and recovery audit anchoring](security-action-audit-anchoring.md).
6. Every other non-null causation ID resolves to either another committed event in the bundle or a durable evidence delivery event, and a committed cause cannot occur after its effect.

Duplicate selected event IDs, incomplete chains and ambiguous references are rejected. The verification result contains counts and Fabric transaction/block metadata, but no raw evidence or credentials.

## Verification command

Run `npm run causal-audit:verify` after `npm run infra:migrate` and `npm run fabric:up`. It runs the audit unit suite, proves the restricted database role and tenant/correlation bounds inside a rolled-back transaction, writes or idempotently reuses five deterministic commitments on Tenant Alpha's local channel, rereads them with the separate Fabric verifier identity, validates the full evidence-to-action chain and confirms that an off-chain score change is rejected.

Run `npm run ledger-privacy:verify` for the T8.9 adversarial boundary. It proves tenant-auditor channel separation and tests both simple raw-record tampering and coordinated off-chain record/hash replacement against the immutable Fabric value. The exact security claims and limitations are documented in [Fabric ledger privacy and tamper detection](../security/fabric-ledger-privacy-and-tamper-detection.md).
