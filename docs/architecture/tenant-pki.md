# Tenant certificate-authority model

The local Compose stack starts one development step-ca instance to prove CA initialization, TLS health and certificate issuance. Its root, intermediate and database persist in the `tenant-trust-step-ca-data` volume. This development CA is not evidence that tenant issuer isolation is complete.

## Issuer hierarchy

A deployment uses one offline platform root and a distinct online intermediate issuing CA for every tenant. Each tenant issuer has its own private key, step-ca configuration, database or isolated database namespace, administrative provisioners and lifecycle state. Tenant intermediates may share the platform trust anchor, but they never share intermediate private keys or provisioner credentials.

The platform root private key remains offline after signing or rotating tenant intermediates. Online application services receive only the public root bundle and the issuer endpoints they need. Production issuer keys should use a KMS or HSM-backed signer; encrypted files in isolated storage are acceptable only for the local prototype.

## Provisioning sequence

1. Complete the durable tenant record and allocate an immutable `issuerId`.
2. Create an isolated issuer state store and key boundary named from the trusted tenant ID.
3. Generate the intermediate private key and certificate-signing request inside that boundary.
4. Sign the constrained intermediate during a platform-root ceremony and record its serial number, SHA-256 fingerprint, validity window and parent root version.
5. Configure one tenant-specific step-ca authority and its administrative provisioner. Bind its advertised URL and accepted names to the tenant issuer record.
6. Start the authority, verify its TLS health and issue a short-lived synthetic probe certificate. Delete the probe key immediately.
7. Activate the issuer only after the stored tenant ID, issuer ID and certificate fingerprints match the trusted provisioning request. Publish the corresponding versioned certificate event.

Certificate issue, renewal and revocation requests resolve the issuer from authenticated tenant context. A caller cannot select another tenant's issuer by sending an issuer ID or URL. Database keys, Redis keys, NATS subjects and audit events retain both tenant and issuer identity.

## Lifecycle and failure behavior

Revocation, suspension and rotation occur within one tenant issuer boundary. Compromise of an intermediate requires suspending that issuer, revoking its intermediate at the platform root, creating a new key and intermediate, and reissuing affected tenant certificates. It must not require another tenant's issuer key or database.

If issuer identity, certificate chain, tenant mapping or revocation state cannot be established, certificate operations fail closed. CA unavailability blocks new issue and renewal requests; it does not make an existing certificate valid or bypass trust and policy checks.

The later tenant-PKI implementation task will automate this sequence. It must create separate issuer instances or equivalent cryptographic isolation and demonstrate that one tenant's provisioner cannot issue, renew or revoke certificates for another tenant.
