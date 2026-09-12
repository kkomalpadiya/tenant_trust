# Shared service contracts

This package owns versioned JSON Schema contracts for security-relevant events and internal security commands. Services validate an event before publishing it and again before applying its effect. Command handlers validate normalized requests after trusted identity context has been attached. The schemas describe data shape; the invariants below define processing behavior that JSON Schema alone cannot express.

`schemas/event-registry.json` maps every supported event name to its validator schema. Producers and consumers use this registry rather than inferring a schema from string parsing.

`schemas/pki/certificate-request.schema.json` defines the normalized certificate issue/renew request, and `schemas/pki/certificate-identity-profile.json` defines the X.509 fields the PKI service derives from trusted tenant and subject identity. The raw caller cannot choose the issuer, SAN, subject, key usage, serial or validity timestamps. See [Certificate identity profile and request contract](../../docs/architecture/certificate-identity-profile.md).

## Identifier rules

Identifiers are opaque lowercase UUIDs with a type prefix. Generate the UUID once when the entity or event is created. Never derive an identifier from a name, email address, certificate subject or other personal data.

| Prefix | Meaning |
| --- | --- |
| `tnt_` | Tenant |
| `sub_` | Subject |
| `crt_` / `iss_` | Certificate / issuer |
| `src_` / `evd_` | Evidence source / evidence record |
| `trn_` | Trust transition |
| `pol_` | Policy version |
| `req_` / `dec_` | Request / access decision |
| `act_` | Security action |
| `evt_` | Immutable event |
| `cor_` | End-to-end correlation |

`eventId` identifies one immutable fact. `aggregateId` identifies the domain record changed by that fact. `correlationId` remains constant across one user or system workflow. `causationId` names the immediate parent event and is `null` only for a root event. These links provide the causal chain used by the audit verifier.

## Idempotency

The command/API boundary creates an `idempotencyKey` from stable operation inputs or accepts a validated client key. Scope it to `(tenantId, producer.service, eventType, idempotencyKey)`. Do not reuse a key for a different operation.

Every consumer records `(consumerName, eventId)` before applying an effect in the same durable transaction where possible. A repeated `eventId` with the same canonical payload is acknowledged without a second effect. The same `eventId` or scoped idempotency key with different canonical content is a conflict that must be rejected and audited. Delivery retries never create a new `eventId`.

Canonical content and hashing rules will be finalized with the audit contract. Producers must not hash ordinary `JSON.stringify` output and assume cross-service stability.

## Time and ordering

All timestamps use RFC 3339 UTC with a trailing `Z`.

- `occurredAt` is when the domain change occurred.
- `recordedAt` is when the producer persisted the event. It must be at or after `occurredAt`, allowing only the explicitly configured clock-skew policy.
- Evidence adds `observedAt` and `expiresAt`. An accepted observation must satisfy `observedAt <= occurredAt <= recordedAt < expiresAt` after the ingestion service applies its allowed skew.
- A timestamp does not resolve concurrent updates. Evidence sources use `sourceSequence`; state-owning services use database versions/locks added with their persistence models.

Consumers must not change security state from an event whose tenant or subject does not match the trusted aggregate state, even when the event passes shape validation.

## Versioning

`schemaVersion` follows semantic versioning and describes the envelope plus payload schema. Event names end in `.v1`, which fixes the transport contract's major version.

- Patch: clarification or validation tightening that does not reject previously valid intended messages.
- Minor: optional additive fields or new event types that old consumers can safely ignore.
- Major: removed/renamed fields, changed meaning, new required fields or incompatible enum changes. Publish a new event major and support an explicit migration window.

Consumers reject unknown major versions. They may accept compatible minor/patch versions only after tests prove that behavior. Persist the original event bytes and version; never silently rewrite historical events.

## Event ownership

| Schema | Producing boundary | Main consumers |
| --- | --- | --- |
| Tenant / subject | Tenant administration | API, PKI, evidence, trust, policy and audit |
| Certificate | PKI lifecycle service | API, trust, policy and audit |
| Evidence | Evidence ingestion | Trust and audit |
| Trust | Trust engine | Policy, orchestration and audit |
| Policy | Policy administration | API/policy enforcement and audit |
| Decision | API policy enforcement point | Orchestration and audit |
| Action | Security action orchestrator | PKI, trust, API/session invalidation and audit |

Raw evidence does not travel in these events. `contentHashSha256` points to the accepted off-chain evidence bytes. Decision events hash a resource identifier rather than exposing it to the ledger pipeline.

## Validation

Run from the repository root:

```powershell
npm test
```

The tests compile every schema, validate one representative event for each domain, reject malformed IDs and timestamps, enforce bounded scores and verify the sample causal chain. Passing schema tests does not authenticate an event; signature verification and trusted transport belong to the evidence and messaging tasks.
