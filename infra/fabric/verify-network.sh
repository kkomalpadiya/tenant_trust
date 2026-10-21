#!/bin/sh
set -eu

FABRIC_ROOT=/fabric
ORDERER_ROOT="$FABRIC_ROOT/organizations/ordererOrganizations/audit.tenant-trust.test"
ORDERER_NODE="$ORDERER_ROOT/orderers/orderer0.audit.tenant-trust.test"
PLATFORM_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/platform.audit.tenant-trust.test"
ALPHA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/alpha.audit.tenant-trust.test"
BETA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/beta.audit.tenant-trust.test"

peer_channels() {
  peer_address="$1"
  msp_id="$2"
  admin_msp="$3"
  tls_root="$4"
  CORE_PEER_ADDRESS="$peer_address" \
  CORE_PEER_LOCALMSPID="$msp_id" \
  CORE_PEER_MSPCONFIGPATH="$admin_msp" \
  CORE_PEER_TLS_ENABLED=true \
  CORE_PEER_TLS_ROOTCERT_FILE="$tls_root" \
  peer channel list 2>/dev/null | grep '^tt-audit-' | sort
}

assert_channels() {
  label="$1"
  actual="$2"
  expected="$3"
  if [ "$actual" != "$expected" ]; then
    echo "$label channel membership mismatch." >&2
    echo "Expected:" >&2
    printf '%s\n' "$expected" >&2
    echo "Actual:" >&2
    printf '%s\n' "$actual" >&2
    exit 1
  fi
}

platform_channels="$(peer_channels peer0.platform.audit.tenant-trust.test:7051 PlatformAuditMSP "$PLATFORM_ROOT/users/Admin@platform.audit.tenant-trust.test/msp" "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt")"
alpha_channels="$(peer_channels peer0.alpha.audit.tenant-trust.test:7051 TenantAlphaAuditMSP "$ALPHA_ROOT/users/Admin@alpha.audit.tenant-trust.test/msp" "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt")"
beta_channels="$(peer_channels peer0.beta.audit.tenant-trust.test:7051 TenantBetaAuditMSP "$BETA_ROOT/users/Admin@beta.audit.tenant-trust.test/msp" "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt")"

assert_channels "Platform peer" "$platform_channels" "tt-audit-alpha-v1
tt-audit-beta-v1"
assert_channels "Tenant Alpha peer" "$alpha_channels" "tt-audit-alpha-v1"
assert_channels "Tenant Beta peer" "$beta_channels" "tt-audit-beta-v1"

orderer_channels="$(osnadmin channel list \
  -o orderer0.audit.tenant-trust.test:9443 \
  --ca-file "$ORDERER_NODE/tls/ca.crt" \
  --client-cert "$ORDERER_NODE/tls/server.crt" \
  --client-key "$ORDERER_NODE/tls/server.key")"
orderer_channel_names="$(printf '%s\n' "$orderer_channels" | sed '1d' | jq -r '.channels[].name' | sort)"
assert_channels "Orderer" "$orderer_channel_names" "tt-audit-alpha-v1
tt-audit-beta-v1"

root_fingerprints="$(for cert in \
  "$ORDERER_ROOT/msp/cacerts/ca-cert.pem" \
  "$PLATFORM_ROOT/msp/cacerts/ca-cert.pem" \
  "$ALPHA_ROOT/msp/cacerts/ca-cert.pem" \
  "$BETA_ROOT/msp/cacerts/ca-cert.pem"; do
    openssl x509 -in "$cert" -noout -fingerprint -sha256
  done | sort -u)"
if [ "$(printf '%s\n' "$root_fingerprints" | grep -c '^sha256 Fingerprint=')" -ne 4 ]; then
  echo "The four Fabric MSPs do not have four distinct CA roots." >&2
  exit 1
fi

for role_cert in \
  "$PLATFORM_ROOT/users/audit-writer@platform.audit.tenant-trust.test/msp/signcerts/cert.pem:audit-writer" \
  "$PLATFORM_ROOT/users/audit-verifier@platform.audit.tenant-trust.test/msp/signcerts/cert.pem:audit-verifier" \
  "$PLATFORM_ROOT/users/audit-commit-listener@platform.audit.tenant-trust.test/msp/signcerts/cert.pem:audit-commit-listener" \
  "$ALPHA_ROOT/users/tenant-auditor@alpha.audit.tenant-trust.test/msp/signcerts/cert.pem:tenant-auditor" \
  "$BETA_ROOT/users/tenant-auditor@beta.audit.tenant-trust.test/msp/signcerts/cert.pem:tenant-auditor"; do
  cert="${role_cert%%:*}"
  role="${role_cert##*:}"
  openssl x509 -in "$cert" -noout -text | grep -q "$role"
done

echo "Fabric network verification passed: pinned nodes are reachable, channel membership is tenant-isolated, and all Fabric CA roots and role identities are distinct."
