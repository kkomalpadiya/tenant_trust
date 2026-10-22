# Fabric ledger privacy and tamper detection

T8.9 tests two separate properties: one tenant cannot read another tenant's ledger, and later changes to the detailed off-chain audit record cannot still match the value committed to Fabric. These properties support audit integrity, but they do not turn a digest into proof that the original real-world evidence was true.

## Tenant ledger boundary

Tenant Alpha and Tenant Beta use different Fabric channels and different tenant MSPs. Each tenant peer joins only its own channel, so it does not receive the other tenant's blocks or public state. The chaincode then applies a second check: `ReadCommitment` accepts the platform `audit-verifier` or the `tenant-auditor` from the MSP assigned to the current channel. A valid tenant-auditor certificate from the other tenant is not query authority.

The platform verifier can query both tenant channels by design because it runs the server-side causal verification service. SaaS users, browsers and tenant-facing API callers receive no Fabric identity and cannot select a channel. The backend derives the channel from the validated tenant ID.

The live privacy gate verifies all of the following:

- each tenant auditor reads its own deterministic commitment;
- Alpha's auditor cannot evaluate a query on Beta's peer and Beta's auditor cannot evaluate one on Alpha's peer;
- a valid Alpha commitment key is absent from Beta state and the valid Beta key is absent from Alpha state;
- rejected cross-tenant queries do not return the other tenant's commitment value;
- a successful public-state read contains exactly the six approved commitment fields and no tenant ID, subject ID, event ID, payload, decision ID or certificate ID.

Separate channels do not hide all metadata from their members. A channel member can observe its channel's transaction timing, submitting organization, activity volume, record class and opaque hashes. Hashing identifiers is not encryption. A party that can guess a low-entropy preimage may test guesses, so the design uses opaque high-entropy identifiers and keeps detailed event content off-chain.

## Tamper cases

The causal verifier starts from the durable off-chain event and recomputes the canonical preimage, event-key hash and commitment hash instead of trusting stored digest columns.

| Change after commit | Verification result |
| --- | --- |
| Raw off-chain event changes but stored preimage and hashes do not | `OFFCHAIN_COMMITMENT_MISMATCH` |
| Raw event, stored preimage and local hashes are changed together | `LEDGER_COMMITMENT_MISMATCH`, because Fabric still contains the original value |
| A different value is submitted under the existing opaque event key | Chaincode rejects it as `CONFLICTING_COMMITMENT` or `CONFLICTING_EVENT_ANCHOR` |
| A selected causal reference is changed | Commitment verification or the evidence/trust/policy/decision/certificate-action link checks fail |
| A pending or failed local delivery is presented as ledger evidence | Verification fails because successful validation code, transaction ID and block number are required |

This means an attacker cannot make an altered detailed record verify merely by recalculating PostgreSQL digest fields. They would also need to replace the immutable committed value under the same Fabric key, which the chaincode's duplicate protection rejects.

## What a commitment proves

For the exact canonicalization profile, channel and event key, a successful verification establishes that:

- the supplied off-chain event bytes produce the same digest stored on Fabric;
- Fabric committed that digest in a successfully validated transaction and retained it at the queried key;
- the selected records in the supplied correlation form the causal links checked by T8.8;
- later byte-level modification of a verified record is detectable, assuming the digest algorithm and trusted verifier implementation remain secure.

## What a commitment does not prove

A matching hash does not establish:

- that a sensor observation, user assertion, certificate claim or other source statement was factually true;
- that the producer was uncompromised, honest or authorized unless the upstream signature and authority checks are also verified;
- that every relevant event was recorded or committed; an omitted event cannot be detected without an independent completeness expectation;
- that a trust model, policy rule or access decision was correct, fair or effective;
- that event timestamps equal real-world occurrence time; Fabric proves ledger ordering and commit metadata, not an external clock observation;
- that confidential values cannot be guessed from a low-entropy domain;
- that colluding authorized organizations could not commit a false record at the outset.

The audit ledger is therefore an integrity anchor, not a truth oracle. Evidence authenticity, freshness, source governance, completeness monitoring and policy evaluation remain separate controls.

## Verification command

Start the reviewed local network with `npm run fabric:up`, then run `npm run ledger-privacy:verify`. The command runs the canonical commitment tests, chaincode tests, causal-verifier tamper tests, the complete live Fabric verification gate and the cross-tenant privacy probes. It is read-only apart from the deterministic idempotent commitments created by the existing Fabric verification gate.
