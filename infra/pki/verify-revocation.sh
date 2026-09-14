#!/bin/sh
set -eu

probe=/tmp/tenant-trust-revocation-probe
rm -rf "$probe"
mkdir -p "$probe"
trap 'rm -rf "$probe"' EXIT

token=$(step ca token tenant-trust-revocation-probe.local \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner platform-admin \
  --password-file /run/secrets/step_ca_password)

step ca certificate tenant-trust-revocation-probe.local \
  "$probe/certificate.crt" \
  "$probe/private.key" \
  --token "$token" \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt

step ca revoke \
  --cert "$probe/certificate.crt" \
  --key "$probe/private.key" \
  --reason "Tenant Trust revocation verification" \
  --reasonCode KeyCompromise \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt

if step ca renew \
  "$probe/certificate.crt" \
  "$probe/private.key" \
  --force \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt \
  >"$probe/renewal-output.txt" 2>&1; then
  echo "Revoked certificate unexpectedly renewed." >&2
  exit 1
fi

echo "Issued, actively revoked and blocked renewal of a temporary Smallstep certificate; probe files were removed."
