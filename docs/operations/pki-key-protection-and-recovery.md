# PKI key protection and issuer recovery

## Protection boundary

The local foundation CA stores its encrypted root and intermediate private keys only in the `STEP_CA_VOLUME_NAME` Docker volume. The generated unlock password stays in the ignored `runtime/secrets/step-ca-password.txt` file. Both private-key files are owned by the `step` account with mode `0600`; application packages receive neither the volume nor the unlock secret. Git ignores private-key extensions, runtime state and the `.ttcab` backup format.

Production tenant issuers must keep one non-exportable intermediate key per tenant in a KMS or HSM boundary. The platform root remains offline and may sign only tenant intermediates. The local volume and encrypted-file workflow is a recovery demonstration, not a production HSM substitute.

## Create a consistent encrypted backup

Use a backup passphrase that is different from the CA unlock password. Store both secrets in an approved password manager or secret manager, with access limited to PKI recovery operators. Put the backup and its passphrase outside the repository and outside synchronized source folders.

Stop the issuer before the snapshot so its configuration and database are consistent:

```powershell
docker compose --env-file .env -f infra/compose/compose.yaml stop step-ca
npm run pki:backup -- --volume tenant-trust-step-ca-data --backup C:\secure-backups\tenant-trust-ca-2026-09-15.ttcab --passphrase-file C:\secure-backups\tenant-trust-backup-passphrase.txt
docker compose --env-file .env -f infra/compose/compose.yaml start step-ca
```

The command refuses a relative or repository-local destination, a running issuer, missing CA files, keys without mode `0600`, an existing output file, and an unpinned or missing image setting. The `.ttcab` envelope uses scrypt-derived AES-256-GCM encryption. Its authenticated header records the creation time, source volume and plaintext archive digest. The command never prints the passphrase or plaintext key material.

Copy the encrypted backup to an access-controlled, versioned backup system. Record its digest, custody approvals and restore-test date in the operational audit system. Keep the separate passphrase under dual control. A backup is not complete until a restore test succeeds.

## Restore for availability loss

Restore only after identifying a non-compromise availability event, such as an accidentally lost local Docker volume. Never overwrite or extract into the old volume. The command authenticates and decrypts the envelope before it creates a new destination volume, rejects a wrong passphrase or changed file, restores key permissions and removes plaintext staging files.

```powershell
npm run pki:restore -- --volume tenant-trust-step-ca-data-restored-v1 --backup C:\secure-backups\tenant-trust-ca-2026-09-15.ttcab --passphrase-file C:\secure-backups\tenant-trust-backup-passphrase.txt
```

Before switching traffic, start the restored issuer with the original CA unlock secret on an isolated endpoint. Confirm the root and intermediate fingerprints against the approved inventory, run health and issuance checks, and verify certificate status/revocation state. Change `STEP_CA_VOLUME_NAME` only after those checks pass. Preserve the old volume for investigation; do not delete it during restore.

## Tenant intermediate compromise

Restoring a compromised issuer reproduces the compromised key and is prohibited. Use this containment and replacement sequence:

1. Open an incident, preserve logs and the affected volume read-only, and identify the tenant, issuer ID, key version and exposure window.
2. Suspend issuance, renewal and revocation credentials for only that issuer. Mark its mapping unavailable so certificate status and protected operations fail closed for the affected tenant.
3. Publish an authenticated issuer-compromise event and invalidate sessions or cached allows derived from its certificates. Other tenant issuers remain online unless evidence shows shared-boundary exposure.
4. During an approved offline-root ceremony, revoke the affected intermediate, generate a new non-exportable key in a new tenant-specific boundary and sign a versioned replacement intermediate.
5. Atomically activate the new issuer mapping. Keep the compromised issuer and its serial namespace permanently retired. Never re-enable it from backup.
6. Reissue eligible tenant certificates with fresh subject keys. Reject old-chain, revoked, wrong-issuer and wrong-tenant certificates throughout the transition.
7. Publish signed replacement, revocation and recovery events with incident correlation and causation IDs. Reconcile the inventory, event outbox and audit commitments before closing containment.
8. Rotate the affected provisioner credentials and any backup or unlock secrets that might have been exposed. Retest tenant isolation, issuance, renewal, status, revocation, event delivery and the complete certificate-lifecycle gate.

## Platform-root compromise

A platform-root incident affects every tenant. Stop all issuer operations, remove the compromised root from future trust, preserve evidence and invoke a platform-wide offline recovery ceremony. Create a new root key in a new HSM/KMS boundary, create new per-tenant intermediate keys, distribute a versioned trust bundle through an authenticated channel, reissue tenant certificates and retire every chain under the compromised root. Do not use a backup of the compromised root to resume signing.

## Local recovery proof

Run:

```powershell
npm run pki-recovery:verify
```

The gate creates a disposable source CA volume, confirms owner-only key permissions, writes an authenticated encrypted backup outside Git, rejects a wrong passphrase without creating a volume, restores into a distinct volume, compares the root identity, starts the recovered CA and issues a fresh disposable certificate. It then removes both volumes, the container, passphrases, ciphertext and plaintext staging data. It never reads, stops or changes the normal `tenant-trust-step-ca-data` volume.

