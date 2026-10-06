# Evidence source enrollment and key registry

This package is the trusted application boundary for enrolling a pre-authorized tenant evidence source and managing its Ed25519 verification keys. It accepts only an authoritative tenant context, requires the `tenant-admin` role and never accepts tenant, actor, fingerprint, state or version fields from a request.

The PostgreSQL repository calls security-definer functions that independently derive tenant and actor identity from transaction-local database context. Enrollment activates an existing `planned` source. Rotation retains the previous public key as a closed key epoch and appends the next version. Revocation retains the selected key and its audit metadata; revoking the active key suspends the source immediately.

Tenant administrators also configure bounded fixed-window quotas, an automatic-suspension threshold and a per-source influence cap through the registry. They can manually suspend a source or resume one only while it still has a matching active verification key. Direct lifecycle and safeguard-field updates are blocked, and every configuration or suspension transition is retained in append-only control history.

Only public Ed25519 key material is stored. Private signing keys remain with the evidence source and must never be submitted to this boundary.

Run `npm run evidence-sources:verify` for key-registry verification and `npm run evidence-safeguards:verify` for flood-control, influence-cap and suspension verification.
