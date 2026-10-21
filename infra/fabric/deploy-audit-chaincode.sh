#!/bin/sh
set -eu

FABRIC_ROOT=/fabric
CHAINCODE_NAME=tenant-trust-audit
CHAINCODE_LABEL=tenant-trust-audit_0.1.0
CHAINCODE_VERSION=0.1.0
CHAINCODE_SEQUENCE=1
PACKAGE_ROOT="$FABRIC_ROOT/chaincode"
PACKAGE_PATH="$PACKAGE_ROOT/$CHAINCODE_LABEL.tar.gz"
PACKAGE_ID_PATH="$PACKAGE_ROOT/$CHAINCODE_NAME.package-id"
ORDERER_ROOT="$FABRIC_ROOT/organizations/ordererOrganizations/audit.tenant-trust.test"
ORDERER_TLS="$ORDERER_ROOT/orderers/orderer0.audit.tenant-trust.test/tls/ca.crt"
PLATFORM_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/platform.audit.tenant-trust.test"
ALPHA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/alpha.audit.tenant-trust.test"
BETA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/beta.audit.tenant-trust.test"

use_peer() {
  export CORE_PEER_ADDRESS="$1"
  export CORE_PEER_LOCALMSPID="$2"
  export CORE_PEER_MSPCONFIGPATH="$3"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_TLS_ROOTCERT_FILE="$4"
}

platform_admin() {
  use_peer peer0.platform.audit.tenant-trust.test:7051 PlatformAuditMSP \
    "$PLATFORM_ROOT/users/Admin@platform.audit.tenant-trust.test/msp" \
    "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt"
}

alpha_admin() {
  use_peer peer0.alpha.audit.tenant-trust.test:7051 TenantAlphaAuditMSP \
    "$ALPHA_ROOT/users/Admin@alpha.audit.tenant-trust.test/msp" \
    "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt"
}

beta_admin() {
  use_peer peer0.beta.audit.tenant-trust.test:7051 TenantBetaAuditMSP \
    "$BETA_ROOT/users/Admin@beta.audit.tenant-trust.test/msp" \
    "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt"
}

package_chaincode() {
  work="$PACKAGE_ROOT/package-work"
  rm -rf "$work"
  mkdir -p "$work/code"
  printf '%s\n' '{"address":"audit-chaincode-{{.peername}}:9999","dial_timeout":"10s","tls_required":false}' > "$work/code/connection.json"
  printf '%s\n' "{\"path\":\"\",\"type\":\"ccaas\",\"label\":\"$CHAINCODE_LABEL\"}" > "$work/metadata.json"
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$work/code" -czf "$work/code.tar.gz" connection.json
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$work" -czf "$PACKAGE_PATH" metadata.json code.tar.gz
  rm -rf "$work"
}

install_for_current_peer() {
  installed="$(peer lifecycle chaincode queryinstalled --output json)"
  if ! printf '%s' "$installed" | jq -e --arg package_id "$PACKAGE_ID" \
    '.installed_chaincodes[]? | select(.package_id == $package_id)' >/dev/null; then
    peer lifecycle chaincode install "$PACKAGE_PATH"
  fi
}

approve_for_current_org() {
  channel="$1"
  approved="$(peer lifecycle chaincode queryapproved -C "$channel" -n "$CHAINCODE_NAME" --sequence "$CHAINCODE_SEQUENCE" --output json 2>/dev/null || true)"
  if [ -n "$approved" ]; then
    if ! printf '%s' "$approved" | jq -e \
      --arg version "$CHAINCODE_VERSION" \
      --arg package_id "$PACKAGE_ID" \
      --argjson sequence "$CHAINCODE_SEQUENCE" \
      '.sequence == $sequence and .version == $version and (.init_required // false) == false and .source.Type.LocalPackage.package_id == $package_id' >/dev/null; then
      echo "Existing $CORE_PEER_LOCALMSPID approval for $channel conflicts with the required definition." >&2
      exit 1
    fi
    return 0
  fi
  peer lifecycle chaincode approveformyorg \
    -o orderer0.audit.tenant-trust.test:7050 \
    --ordererTLSHostnameOverride orderer0.audit.tenant-trust.test \
    --tls --cafile "$ORDERER_TLS" \
    --channelID "$channel" \
    --name "$CHAINCODE_NAME" \
    --version "$CHAINCODE_VERSION" \
    --package-id "$PACKAGE_ID" \
    --sequence "$CHAINCODE_SEQUENCE" \
    --channel-config-policy /Channel/Application/Endorsement \
    --waitForEvent
}

commit_channel() {
  channel="$1"
  tenant_msp="$2"
  tenant_peer="$3"
  tenant_tls="$4"
  platform_admin
  committed="$(peer lifecycle chaincode querycommitted -C "$channel" -n "$CHAINCODE_NAME" --output json 2>/dev/null || true)"
  if [ -n "$committed" ]; then
    if ! printf '%s' "$committed" | jq -e \
      --arg version "$CHAINCODE_VERSION" \
      --argjson sequence "$CHAINCODE_SEQUENCE" \
      '.sequence == $sequence and .version == $version and (.init_required // false) == false' >/dev/null; then
      echo "Committed definition for $channel conflicts with the required version or sequence." >&2
      exit 1
    fi
    return 0
  fi

  readiness="$(peer lifecycle chaincode checkcommitreadiness \
    --channelID "$channel" \
    --name "$CHAINCODE_NAME" \
    --version "$CHAINCODE_VERSION" \
    --sequence "$CHAINCODE_SEQUENCE" \
    --channel-config-policy /Channel/Application/Endorsement \
    --output json)"
  if ! printf '%s' "$readiness" | jq -e \
    --arg platform PlatformAuditMSP --arg tenant "$tenant_msp" \
    '.approvals[$platform] == true and .approvals[$tenant] == true' >/dev/null; then
    echo "Both channel organizations have not approved $CHAINCODE_NAME on $channel." >&2
    exit 1
  fi

  peer lifecycle chaincode commit \
    -o orderer0.audit.tenant-trust.test:7050 \
    --ordererTLSHostnameOverride orderer0.audit.tenant-trust.test \
    --tls --cafile "$ORDERER_TLS" \
    --channelID "$channel" \
    --name "$CHAINCODE_NAME" \
    --version "$CHAINCODE_VERSION" \
    --sequence "$CHAINCODE_SEQUENCE" \
    --channel-config-policy /Channel/Application/Endorsement \
    --peerAddresses peer0.platform.audit.tenant-trust.test:7051 \
    --tlsRootCertFiles "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt" \
    --peerAddresses "$tenant_peer" \
    --tlsRootCertFiles "$tenant_tls"
}

mkdir -p "$PACKAGE_ROOT"
package_chaincode
PACKAGE_ID="$(peer lifecycle chaincode calculatepackageid "$PACKAGE_PATH")"
printf '%s\n' "$PACKAGE_ID" > "$PACKAGE_ID_PATH"

platform_admin
install_for_current_peer
alpha_admin
install_for_current_peer
beta_admin
install_for_current_peer

platform_admin
approve_for_current_org tt-audit-alpha-v1
approve_for_current_org tt-audit-beta-v1
alpha_admin
approve_for_current_org tt-audit-alpha-v1
beta_admin
approve_for_current_org tt-audit-beta-v1

commit_channel tt-audit-alpha-v1 TenantAlphaAuditMSP \
  peer0.alpha.audit.tenant-trust.test:7051 \
  "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt"
commit_channel tt-audit-beta-v1 TenantBetaAuditMSP \
  peer0.beta.audit.tenant-trust.test:7051 \
  "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt"

echo "Audit chaincode package $PACKAGE_ID is installed and defined on both tenant channels."
