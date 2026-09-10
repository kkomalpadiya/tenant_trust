#!/bin/sh
set -eu

config=/home/step/config/ca.json
if [ -f "$config" ]; then
  echo "step-ca is already initialized; preserving the existing CA identity."
  exit 0
fi

step ca init \
  --name "$STEP_CA_NAME" \
  --dns "$STEP_CA_DNS_NAMES" \
  --address "$STEP_CA_ADDRESS" \
  --provisioner "$STEP_CA_PROVISIONER" \
  --password-file /run/secrets/step_ca_password \
  --provisioner-password-file /run/secrets/step_ca_password

test -f /home/step/certs/root_ca.crt
test -f /home/step/certs/intermediate_ca.crt
test -f /home/step/secrets/intermediate_ca_key
echo "Initialized the local platform CA in the tenant-trust-step-ca-data volume."
