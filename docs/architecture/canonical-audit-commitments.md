# Canonical audit commitments and event selection

T8.3 defines the exact records that may be committed to the tenant audit ledgers and the byte contract used to produce a commitment. It does not deploy chaincode or submit transactions. PostgreSQL and the signed application-event stream remain authoritative for detailed records; Fabric receives only the minimal public value defined here.

## Selection boundary

Only a durable event that passes its versioned schema may enter the commitment pipeline. The authoritative event envelope, including its correlation and causation links, is the off-chain preimage.

| Record class exposed on-chain | Selected event types | Off-chain authority and verification value |
| --- | --- | --- |
| `certificate-lifecycle` | `certificate.requested.v1`, `certificate.issued.v1`, `certificate.renewed.v1`, `certificate.superseded.v1`, `certificate.revoked.v1`, `certificate.expired.v1` | Signed lifecycle events derived from the append-only certificate lifecycle record. They bind the certificate state, issuer confirmation, actor and immediate lifecycle cause. |
| `trust-transition` | `trust.updated.v1` | The append-only trust transition and canonical explanation hash. Evidence identifiers, model version and configuration version preserve the off-chain explanation chain without publishing evidence. |
| `policy-change` | `policy.published.v1`, `policy.activated.v1`, `policy.rolled-back.v1` | The tenant policy lifecycle event. It binds the immutable policy version, bundle digest, activation state and replacement link. |
| `access-decision` | `access.decided.v1` | The canonical decision provenance event. It binds the request, certificate, trust transition, active policy, resource hash, outcome and any step-up proof hash. Every contract-valid outcome is selected. |
| `security-action` | `security-action.requested.v1`, `security-action.succeeded.v1`, `security-action.failed.v1` | The durable action request and each persisted attempt outcome. It links the action ID to its decision or governed recovery authorization, the requested-action event, target certificate, reason, failure and matching certificate lifecycle event when applicable. |

Evidence acceptance/rejection events, tenant and subject administration events, API request logs, raw observations, credentials, policy input documents and mutable current-state rows are not selected. In particular, neither `evidence.accepted.v1` nor `evidence.rejected.v1` may enter the ledger pipeline. A trust commitment carries only the hash of the schema-valid trust event; its evidence IDs and explanation remain inside the off-chain preimage.

## Canonical preimage

The commitment preimage is this object:

```json
{
  "schemaVersion": "1.0.0",
  "canonicalizationProfile": "tenant-trust-audit-commitment-json-v1",
  "channelName": "tt-audit-alpha-v1",
  "event": "<complete schema-valid selected event envelope>"
}
```

Objects are serialized with keys in ascending JavaScript string order. Arrays preserve their declared order. Strings, booleans, null and finite numbers use JSON encoding. Sparse arrays, `undefined`, non-finite numbers, bigint values, symbols, functions and non-plain objects are rejected. The resulting string is UTF-8 encoded. The project profile is deliberately named rather than claiming interchangeability with a different canonical-JSON standard.

The payload commitment is:

```text
SHA-256(UTF8("tenant-trust:audit-commitment:v1\n" || canonicalPreimageJson))
```

The opaque event lookup hash is:

```text
SHA-256(UTF8("tenant-trust:audit-event-key:v1\n" || canonicalJson({channelName,eventId,tenantId})))
```

Domain separation prevents the same bytes from being interpreted as both a payload commitment and an event lookup key. Binding both hashes to the tenant channel prevents a valid commitment from being copied to another tenant ledger without detection.

## Public Fabric key and value

The chaincode task must accept only the already-derived public key and value. It must never receive the preimage or a plain tenant, subject, resource, certificate, decision, action or event identifier in proposal arguments, because Fabric transaction inputs are retained with the transaction.

```text
audit~<recordType>~<eventKeyHashSha256>
```

```json
{
  "schemaVersion": "1.0.0",
  "recordType": "trust-transition",
  "eventKeyHashSha256": "<64 lowercase hexadecimal characters>",
  "commitmentHashSha256": "<64 lowercase hexadecimal characters>",
  "canonicalizationProfile": "tenant-trust-audit-commitment-json-v1",
  "digestAlgorithm": "sha256"
}
```

The five broad record classes are the only semantic detail placed in public state. The exact event type is not copied, although a channel member can infer it when a class currently contains only one selected type. Tenant ID, event ID, subject ID, resource identity, score, decision outcome, reason, action and application timestamps stay out of the value. Fabric transaction metadata still reveals transaction timing, submitting identity and activity volume to channel members; hashing is an integrity control, not encryption or traffic-flow concealment.

## Idempotency and verification

One event maps to one deterministic ledger key. A retry with the same event and channel produces identical bytes. T8.4 must permit an exact replay and reject an attempt to replace an existing key with a different value. T8.5 must retain the preimage off-chain, submit only the six approved value fields and mark success only after commit confirmation. T8.9 can reconstruct the canonical preimage, recompute both hashes and compare them with the committed key/value. Changing any committed off-chain field then causes verification to fail, while the correlation, causation, evidence, model, policy, decision and action links remain available to authorized off-chain auditors.

Hash verification proves that the presented off-chain bytes match the earlier commitment. It does not prove that the original evidence was true, and it does not protect a low-entropy secret placed in a preimage from guessing attacks. Raw evidence and secrets therefore remain outside both the selected events and the ledger submission boundary.
