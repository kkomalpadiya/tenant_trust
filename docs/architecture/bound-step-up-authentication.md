# Bound step-up authentication

## Security boundary

Sensitive adaptive-policy operations use a separately enrolled Ed25519 possession factor. The mTLS certificate still authenticates the caller and establishes tenant/subject context; it is not reused as the second factor. A challenge is signed by the selected factor's private key, while Tenant Trust retains only its public key.

The server generates a 256-bit nonce, challenge ID and opaque session ID. The canonical signed document includes the tenant, subject, requested action, selected factor, session hash, nonce, issue time and expiry. Changing any binding invalidates the signature. Challenges expire after 120 seconds.

## Proof lifecycle

After signature verification, the API returns an opaque `sup_...` proof ID. PostgreSQL stores only its SHA-256 hash. The proof expires after 300 seconds and is bound to the challenge tenant, subject, action and session hash.

The client presents the proof ID and session ID in `x-step-up-proof` and `x-step-up-session` on the sensitive request. Inside the same tenant transaction used for the protected operation, `audit.consume_step_up_proof` atomically changes an unused proof to consumed. Concurrent or later replay matches no row. A failed OPA decision or protected query rolls the transaction back, so a system failure does not strand a valid proof.

OPA receives only the validated proof metadata. It checks `valid` status, tenant, subject, action, both hashes, verification time, expiry and the tenant policy's maximum age before changing a `STEP_UP` result to `ALLOW`. All other certificate, authority, role, sensitivity, trust and score checks remain mandatory.

## HTTP flow

1. Enroll an Ed25519 public key with `identity.enroll_step_up_factor`; the private key remains in the user's authenticator.
2. `POST /v1/step-up/challenges` with `action` and the selected `factorId`.
3. Sign the canonical JSON produced by `createStepUpSigningPayload` and send it to `POST /v1/step-up/challenges/{challengeId}/verifications` as `signatureBase64url`.
4. Send the returned proof ID and the challenge response's session ID on exactly one matching sensitive request.

Challenge, verification and sensitive-operation endpoints require the existing trusted mTLS gateway identity. Responses are `no-store`, raw proofs are not logged or sent to OPA, and invalid presentations return the existing generic access-denied response.

## Verification

Run `npm run step-up-authentication:verify` after `npm run infra:migrate`. It checks real Ed25519 signing, binding tamper rejection, policy acceptance and rejection, and PostgreSQL single-use behavior including cross-action, cross-session and cross-tenant attempts.
