# Tenant Trust API reference

## Boundary and conventions

The Fastify application is exported from `apps/api/src/app.mjs`. Production-mode protected routes require a trusted gateway mTLS result. The API does not accept bearer tokens, cookies, caller-selected roles or caller-selected tenant authority. `POST /v1/evidence` authenticates the signed source envelope instead of a user session.

Every response includes server-generated `x-request-id`, `x-correlation-id`, `cache-control: no-store` and `pragma: no-cache` headers. Protected failures use a bounded body and do not disclose tenant, subject, resource or policy details:

```json
{ "error": { "code": "ACCESS_DENIED" } }
```

Common error codes are `INVALID_REQUEST` (400), `CLIENT_CERTIFICATE_REQUIRED` or `CERTIFICATE_NOT_ACCEPTED` (401), `ACCESS_DENIED` (403), `IDEMPOTENCY_CONFLICT` (409), `REQUEST_TOO_LARGE` (413), `EVIDENCE_REJECTED` (422) and `SERVICE_UNAVAILABLE` (503).

## Protected SaaS routes

| Method and route | Purpose | Request | Success |
| --- | --- | --- | --- |
| `GET /v1/profile` | Read the authenticated subject's tenant profile | No query parameters or body | `200` with `{ "profile": { ... } }` |
| `GET /v1/tenant-records` | List records visible to the authenticated subject | No query parameters or body | `200` with `{ "records": [ ... ] }` |
| `GET /v1/tenant-records/{recordId}` | Read one tenant-scoped record | `recordId` must use the `res_<uuid>` form | `200` with `{ "record": { ... } }` |
| `POST /v1/tenant-records/export` | Export one to 25 authorized records | `Idempotency-Key` header and `{ "recordIds": ["res_<uuid>"] }`; adaptive mode may also require the step-up headers below | `200` with operation metadata and records |
| `POST /v1/admin/membership-reviews` | Run a tenant-admin membership review | `Idempotency-Key` header and `{ "subjectId": "sub_<uuid>" }`; adaptive mode may require step-up | `200` with operation metadata |

The export and membership-review endpoints reject unknown fields, repeated record IDs, empty arrays, more than 25 records and malformed IDs. Reusing an idempotency key with a different normalized request returns `409 IDEMPOTENCY_CONFLICT`.

## Step-up routes

These routes are present when the repository supplies the step-up service.

### `POST /v1/step-up/challenges`

Request:

```json
{
  "action": "record:export",
  "factorId": "suf_<uuid>"
}
```

`action` is `record:export` or `tenant:admin`. The response is `200` with `{ "stepUpChallenge": { ... } }`. The challenge is bound to tenant, subject, action, factor and session context and expires after 120 seconds.

### `POST /v1/step-up/challenges/{challengeId}/verifications`

Request:

```json
{ "signatureBase64url": "<86-character Ed25519 signature>" }
```

The response is `200` with `{ "stepUpProof": { ... } }`. Present the returned proof and session identifiers as `X-Step-Up-Proof` and `X-Step-Up-Session` on the bound sensitive operation. The proof expires after 300 seconds and is single-use.

## Signed evidence route

### `POST /v1/evidence`

The body is the versioned signed envelope defined by `packages/contracts/schemas/evidence/signed-evidence-envelope.schema.json`. The maximum encoded envelope is 65,536 bytes and the maximum canonical payload is 32,768 bytes. The service verifies the Ed25519 signature over the repository's canonicalization profile and requires an active source and active source key.

Accepted evidence returns `202`:

```json
{
  "evidence": {
    "status": "accepted",
    "eventId": "evt_<uuid>"
  }
}
```

Malformed schema returns 400, oversized content returns 413, invalid authority, signature, freshness or replay returns 422, and unavailable ingestion state returns 503. The response never echoes the raw evidence payload.

## Authorization behavior

Protected operations first apply the canonical role and ownership matrix. Adaptive mode then calls OPA with immutable certificate, tenant, resource, request and trust state. `ALLOW` runs the operation, `STEP_UP` requires a valid bound proof, and `DENY` or `QUARANTINE` prevents it. A high trust score cannot override an invalid certificate, suspended tenant, missing membership or cross-tenant resource boundary.

## Implementation references

- Route definitions and bounded errors: `apps/api/src/app.mjs`
- Tenant-scoped repository behavior: `apps/api/src/repository.mjs`
- Request timeout, idempotency and stateless mTLS rules: `apps/api/src/request-safeguards.mjs`
- OPA input and output enforcement: `apps/api/src/policy-enforcement.mjs`
- Step-up cryptographic contract: `apps/api/src/step-up-authentication.mjs`
- Signed evidence schema and invariants: `packages/contracts/README.md`
