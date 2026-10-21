#!/bin/sh
set -eu

FABRIC_ROOT=/fabric
ARTIFACTS="$FABRIC_ROOT/channel-artifacts"
ORDERER_ROOT="$FABRIC_ROOT/organizations/ordererOrganizations/audit.tenant-trust.test"
ORDERER_NODE="$ORDERER_ROOT/orderers/orderer0.audit.tenant-trust.test"

mkdir -p "$ARTIFACTS"

wait_for_orderer() {
  attempt=1
  while [ "$attempt" -le 30 ]; do
    if osnadmin channel list \
      -o orderer0.audit.tenant-trust.test:9443 \
      --ca-file "$ORDERER_NODE/tls/ca.crt" \
      --client-cert "$ORDERER_NODE/tls/server.crt" \
      --client-key "$ORDERER_NODE/tls/server.key" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  echo "Timed out waiting for the orderer administration endpoint." >&2
  exit 1
}

wait_for_peer() {
  peer_address="$1"
  tls_root="$2"
  attempt=1
  while [ "$attempt" -le 30 ]; do
    if CORE_PEER_ADDRESS="$peer_address" CORE_PEER_TLS_ENABLED=true CORE_PEER_TLS_ROOTCERT_FILE="$tls_root" peer node status >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  echo "Timed out waiting for $peer_address." >&2
  exit 1
}

generate_block() {
  channel="$1"
  profile="$2"
  block="$ARTIFACTS/$channel.block"
  if [ ! -f "$block" ]; then
    FABRIC_CFG_PATH=/etc/hyperledger/fabric-config configtxgen \
      -profile "$profile" \
      -channelID "$channel" \
      -outputBlock "$block"
  fi
}

join_orderer() {
  channel="$1"
  block="$ARTIFACTS/$channel.block"
  if ! osnadmin channel list \
    -o orderer0.audit.tenant-trust.test:9443 \
    --ca-file "$ORDERER_NODE/tls/ca.crt" \
    --client-cert "$ORDERER_NODE/tls/server.crt" \
    --client-key "$ORDERER_NODE/tls/server.key" 2>/dev/null | grep -q "\"name\": \"$channel\""; then
    osnadmin channel join \
      --channelID "$channel" \
      --config-block "$block" \
      -o orderer0.audit.tenant-trust.test:9443 \
      --ca-file "$ORDERER_NODE/tls/ca.crt" \
      --client-cert "$ORDERER_NODE/tls/server.crt" \
      --client-key "$ORDERER_NODE/tls/server.key"
  fi
}

join_peer() {
  channel="$1"
  peer_address="$2"
  msp_id="$3"
  admin_msp="$4"
  tls_root="$5"
  block="$ARTIFACTS/$channel.block"
  if ! CORE_PEER_ADDRESS="$peer_address" \
    CORE_PEER_LOCALMSPID="$msp_id" \
    CORE_PEER_MSPCONFIGPATH="$admin_msp" \
    CORE_PEER_TLS_ENABLED=true \
    CORE_PEER_TLS_ROOTCERT_FILE="$tls_root" \
    peer channel list 2>/dev/null | grep -qx "$channel"; then
    CORE_PEER_ADDRESS="$peer_address" \
    CORE_PEER_LOCALMSPID="$msp_id" \
    CORE_PEER_MSPCONFIGPATH="$admin_msp" \
    CORE_PEER_TLS_ENABLED=true \
    CORE_PEER_TLS_ROOTCERT_FILE="$tls_root" \
    peer channel join -b "$block"
  fi
}

PLATFORM_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/platform.audit.tenant-trust.test"
ALPHA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/alpha.audit.tenant-trust.test"
BETA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/beta.audit.tenant-trust.test"

wait_for_orderer
wait_for_peer peer0.platform.audit.tenant-trust.test:7051 "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt"
wait_for_peer peer0.alpha.audit.tenant-trust.test:7051 "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt"
wait_for_peer peer0.beta.audit.tenant-trust.test:7051 "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt"

generate_block tt-audit-alpha-v1 TenantAlphaAuditChannel
generate_block tt-audit-beta-v1 TenantBetaAuditChannel
join_orderer tt-audit-alpha-v1
join_orderer tt-audit-beta-v1

join_peer tt-audit-alpha-v1 peer0.platform.audit.tenant-trust.test:7051 PlatformAuditMSP "$PLATFORM_ROOT/users/Admin@platform.audit.tenant-trust.test/msp" "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt"
join_peer tt-audit-beta-v1 peer0.platform.audit.tenant-trust.test:7051 PlatformAuditMSP "$PLATFORM_ROOT/users/Admin@platform.audit.tenant-trust.test/msp" "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt"
join_peer tt-audit-alpha-v1 peer0.alpha.audit.tenant-trust.test:7051 TenantAlphaAuditMSP "$ALPHA_ROOT/users/Admin@alpha.audit.tenant-trust.test/msp" "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt"
join_peer tt-audit-beta-v1 peer0.beta.audit.tenant-trust.test:7051 TenantBetaAuditMSP "$BETA_ROOT/users/Admin@beta.audit.tenant-trust.test/msp" "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt"

echo "Created and joined both tenant audit channels."
