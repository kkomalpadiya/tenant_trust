# Tenant certificate-authority hierarchy

## Scope and current state

The committed definition in `infra/pki/tenant-ca-hierarchy.json` is the source of truth for the planned Tenant Alpha and Tenant Beta issuer boundaries. It defines public trust references, opaque key and credential references, authorization identities and isolation boundaries. It contains no private keys, passwords or provisioner credentials.

The local Compose stack still runs one development step-ca instance for foundation health. The T3.3 verification gate separately creates an ephemeral platform root and distinct Alpha and Beta intermediates, issues real tenant-bound leaves, and removes all generated key material. The reusable application authorization and verification boundary is defined in [Certificate request and issuance](certificate-issuance.md). Long-running tenant-authority deployment remains separate from the foundation CA.

## Hierarchy and trust

The prototype uses one offline platform root and one online intermediate issuing CA per tenant:

```text
Tenant Trust platform root v1 (offline; signs tenant intermediates only)
|-- Tenant Alpha intermediate v1 (online; Alpha certificate lifecycle only)
`-- Tenant Beta intermediate v1 (online; Beta certificate lifecycle only)
```

Application trust stores receive the public platform-root bundle. They do not receive the root private key or any intermediate private key. A leaf certificate is trusted only when its chain reaches the configured root version and its immediate issuer matches the active issuer mapping for the authenticated tenant. Sharing a root trust anchor does not permit an Alpha intermediate to act for Beta: tenant and subject binding remains part of certificate validation and authorization.

The platform root is unavailable to online services and may sign only tenant intermediate certificates. A root rotation creates a new versioned public bundle. Existing and replacement intermediates retain the parent root version used to sign them so validation and recovery do not infer trust from a filename or current default.

## Issuer mapping contract

Each manifest entry must match one row in `identity.tenant_issuer_mappings` by both `tenant_id` and `issuer_id`. The demonstration entries remain `planned` until a later provisioning workflow creates the authority and records verified certificate fingerprints. Activation must fail unless all of these values agree:

- trusted tenant ID and immutable issuer ID;
- issuer name and HTTPS authority URL;
- parent root ID and version;
- intermediate certificate fingerprint and serial obtained from the created certificate;
- authority TLS identity and configured DNS name;
- dedicated state, configuration, key, provisioner and service-principal boundaries.

Certificate lifecycle code starts with validated tenant context, then resolves the mapping. An issuer ID, authority URL, tenant header, path value, query value, request-body field or resource identifier supplied by a caller is only a consistency claim. It cannot select or replace the trusted mapping. A mismatch receives the same non-enumerating denial as any other cross-tenant request.

The two planned database mappings intentionally use different non-routable `.invalid` authority URLs. The T3.3 integration scenario supplies active in-memory mappings only after its isolated authorities exist; it does not falsely activate the planned database rows. A later long-running deployment must replace each placeholder with its deployed internal authority name and verified certificate fingerprint as one activation step.

## Isolation boundaries

Each tenant issuer has a unique value for every item below. Reuse across tenants is a verification failure.

| Boundary | Required separation |
| --- | --- |
| Authority endpoint and DNS names | One routable internal identity per tenant issuer |
| CA state | Separate step-ca database or equivalently isolated database namespace and access identity |
| Configuration | Separate authority configuration and accepted-name set |
| Intermediate key | Separate non-exportable key reference and encryption boundary |
| Provisioner | Separate name and credential reference |
| Application caller | Separate certificate-lifecycle service principal restricted to one issuer |

Separate directories inside one broadly writable process are not sufficient. The deployed process, volume or KMS policy must prevent the Alpha authority and service principal from reading or using Beta key, state or provisioner material, and vice versa.

## Issuer authorization

| Actor | Allowed authority | Direct CA operations |
| --- | --- | --- |
| Platform PKI operator | Provision, activate, suspend, rotate and retire tenant issuer infrastructure; perform the offline root ceremony | Tenant-intermediate lifecycle only; no tenant business-record access |
| Tenant certificate-lifecycle service principal | The single issuer mapped from its trusted tenant context | Issue, renew and revoke through the application lifecycle workflow |
| Tenant administrator | Request permitted certificate lifecycle actions for subjects in the administrator's tenant | None; no provisioner credential, key access or caller-selected issuer |
| Tenant member | Request only the subject operations later allowed by policy | None |
| Foundation `platform-admin` provisioner | Development bootstrap CA only | Temporary foundation probe issuance; never accepted as a tenant issuer |

Tenant administration and CA execution are deliberately separate. Application authorization, including subject eligibility and later step-up requirements, occurs before the per-tenant service principal calls the CA. The CA credential alone is not proof that a request was authorized.

## Key and credential custody

- The platform-root private key stays offline, non-exportable and outside Git. Production should use an HSM or KMS-backed signer. The local research ceremony may use an encrypted offline file held outside the running stack.
- Each tenant intermediate uses its own non-exportable key. Production should use a tenant-specific HSM/KMS policy. The local prototype may use an encrypted file only inside that tenant's isolated CA state volume.
- Each provisioner credential is stored in a separate runtime secret and mounted only into the matching certificate-lifecycle service. It is never stored in the manifest, environment template, logs, events, database rows or test fixtures.
- Database rows and the committed manifest contain identifiers, public certificate metadata and opaque references only. Key export, secret recovery and cross-tenant secret mounts are prohibited.
- Backup and recovery preserve tenant separation, authenticated encryption and access policy. The local recovery command requires a stopped issuer, a destination outside Git and a separate passphrase, then restores only into a new empty volume while retaining owner-only key permissions. The disposable recovery gate proves the restored CA keeps the same public trust identity and can issue a fresh certificate. See [PKI key protection and issuer recovery](../operations/pki-key-protection-and-recovery.md).

## Lifecycle and failure behavior

Issuer suspension blocks issue and renewal immediately. Revocation requests that cannot reach the CA remain visibly pending or failed; they are never reported as completed. Missing or inconsistent tenant context, mapping, chain, root version, fingerprint, state or authorization fails closed.

Compromise of a tenant intermediate suspends only that issuer, restricts affected application access, revokes the intermediate during a platform-root ceremony, creates a fresh key and intermediate, and reissues affected tenant certificates. No step requires another tenant's key, provisioner credential or state store. Compromise of the platform root affects every tenant and requires a platform-wide root recovery and trust-bundle transition.

Availability restoration and compromise recovery are deliberately separate. An authenticated backup may recover lost state only when compromise has been ruled out. Restoring a compromised key would preserve attacker authority, so issuer or root compromise always creates new keys and permanently retires the affected chain.

Tenant suspension prevents new certificate operations even if its CA is healthy. Tenant teardown retires the mapping but retains the issuer identity and public metadata needed for historical audit verification. Revoked certificates and retired issuers never return to an active state.

## Verification

Run `npm run pki-definition:verify`. The verifier checks that the platform root is offline and limited to signing tenant intermediates; Alpha and Beta have unique tenant, issuer, endpoint, state, configuration, key, provisioner, credential and service-principal boundaries; issuer selection comes only from validated tenant context; the manifest matches the planned database seed mappings; and no private key, password, token or secret field is committed.

The static verifier is part of `npm run foundation:check` and the disposable `npm run foundation:clean` path. `npm run certificate-issuance:verify` adds real ephemeral Alpha/Beta issuers and live cross-tenant denial tests while keeping all generated keys outside Git. Passing these gates does not claim that long-running tenant authorities or production HSM/KMS controls have been deployed.
