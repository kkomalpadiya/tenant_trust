#!/bin/sh
set -eu

probe=/tmp/tenant-trust-issuance-probe
rm -rf "$probe"
mkdir -p "$probe"
trap 'rm -rf "$probe"' EXIT

token=$(step ca token tenant-trust-probe.local \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner platform-admin \
  --password-file /run/secrets/step_ca_password)

step ca certificate tenant-trust-probe.local \
  "$probe/certificate.crt" \
  "$probe/private.key" \
  --token "$token" \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt

step certificate verify "$probe/certificate.crt" \
  --roots /home/step/certs/root_ca.crt

echo "Issued and verified a temporary certificate; the probe key and certificate were removed."
