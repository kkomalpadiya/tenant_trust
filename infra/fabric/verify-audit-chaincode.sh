#!/bin/sh
set -eu

FABRIC_ROOT=/fabric
CHAINCODE_NAME=tenant-trust-audit
ORDERER_ROOT="$FABRIC_ROOT/organizations/ordererOrganizations/audit.tenant-trust.test"
ORDERER_TLS="$ORDERER_ROOT/orderers/orderer0.audit.tenant-trust.test/tls/ca.crt"
PLATFORM_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/platform.audit.tenant-trust.test"
ALPHA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/alpha.audit.tenant-trust.test"
BETA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/beta.audit.tenant-trust.test"
ALPHA_EVENT_HASH=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALPHA_COMMITMENT_HASH=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ALPHA_CONFLICT_HASH=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
BETA_EVENT_HASH=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
BETA_COMMITMENT_HASH=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

use_identity() {
  export CORE_PEER_ADDRESS="$1"
  export CORE_PEER_LOCALMSPID="$2"
  export CORE_PEER_MSPCONFIGPATH="$3"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_TLS_ROOTCERT_FILE="$4"
}

platform_writer() {
  use_identity peer0.platform.audit.tenant-trust.test:7051 PlatformAuditMSP \
    "$PLATFORM_ROOT/users/audit-writer@platform.audit.tenant-trust.test/msp" \
    "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt"
}

platform_verifier() {
  use_identity peer0.platform.audit.tenant-trust.test:7051 PlatformAuditMSP \
    "$PLATFORM_ROOT/users/audit-verifier@platform.audit.tenant-trust.test/msp" \
    "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt"
}

alpha_auditor() {
  use_identity peer0.alpha.audit.tenant-trust.test:7051 TenantAlphaAuditMSP \
    "$ALPHA_ROOT/users/tenant-auditor@alpha.audit.tenant-trust.test/msp" \
    "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt"
}

beta_auditor() {
  use_identity peer0.beta.audit.tenant-trust.test:7051 TenantBetaAuditMSP \
    "$BETA_ROOT/users/tenant-auditor@beta.audit.tenant-trust.test/msp" \
    "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt"
}

commitment_json() {
  record_type="$1"
  event_hash="$2"
  commitment_hash="$3"
  jq -cn \
    --arg record_type "$record_type" \
    --arg event_hash "$event_hash" \
    --arg commitment_hash "$commitment_hash" \
    '{canonicalizationProfile:"tenant-trust-audit-commitment-json-v1",commitmentHashSha256:$commitment_hash,digestAlgorithm:"sha256",eventKeyHashSha256:$event_hash,recordType:$record_type,schemaVersion:"1.0.0"}'
}

invoke_commitment() {
  channel="$1"
  tenant_peer="$2"
  tenant_tls="$3"
  value="$4"
  invocation="$(jq -cn --arg value "$value" '{function:"TenantTrustAudit:CommitCommitment",Args:[$value]}')"
  peer chaincode invoke \
    -o orderer0.audit.tenant-trust.test:7050 \
    --ordererTLSHostnameOverride orderer0.audit.tenant-trust.test \
    --tls --cafile "$ORDERER_TLS" \
    -C "$channel" -n "$CHAINCODE_NAME" \
    --peerAddresses peer0.platform.audit.tenant-trust.test:7051 \
    --tlsRootCertFiles "$PLATFORM_ROOT/peers/peer0.platform.audit.tenant-trust.test/tls/ca.crt" \
    --peerAddresses "$tenant_peer" \
    --tlsRootCertFiles "$tenant_tls" \
    --waitForEvent --waitForEventTimeout 30s \
    -c "$invocation" 2>&1
}

query_commitment() {
  channel="$1"
  record_type="$2"
  event_hash="$3"
  invocation="$(jq -cn --arg record_type "$record_type" --arg event_hash "$event_hash" '{function:"TenantTrustAudit:ReadCommitment",Args:[$record_type,$event_hash]}')"
  peer chaincode query -C "$channel" -n "$CHAINCODE_NAME" -c "$invocation" 2>&1
}

assert_definition() {
  channel="$1"
  definition="$(peer lifecycle chaincode querycommitted -C "$channel" -n "$CHAINCODE_NAME" --output json)"
  printf '%s' "$definition" | jq -e '.sequence == 1 and .version == "0.1.0" and (.init_required // false) == false' >/dev/null
}

assert_query_value() {
  actual="$1"
  expected_event_hash="$2"
  expected_commitment_hash="$3"
  printf '%s' "$actual" | jq -e \
    --arg event_hash "$expected_event_hash" \
    --arg commitment_hash "$expected_commitment_hash" \
    '.schemaVersion == "1.0.0" and .eventKeyHashSha256 == $event_hash and .commitmentHashSha256 == $commitment_hash and length == 6' >/dev/null
}

platform_verifier
assert_definition tt-audit-alpha-v1
assert_definition tt-audit-beta-v1

alpha_value="$(commitment_json trust-transition "$ALPHA_EVENT_HASH" "$ALPHA_COMMITMENT_HASH")"
beta_value="$(commitment_json access-decision "$BETA_EVENT_HASH" "$BETA_COMMITMENT_HASH")"
platform_writer
first_alpha="$(invoke_commitment tt-audit-alpha-v1 peer0.alpha.audit.tenant-trust.test:7051 "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt" "$alpha_value")"
printf '%s\n' "$first_alpha" | grep -Eq 'status.*(created|duplicate)'
second_alpha="$(invoke_commitment tt-audit-alpha-v1 peer0.alpha.audit.tenant-trust.test:7051 "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt" "$alpha_value")"
printf '%s\n' "$second_alpha" | grep -q 'duplicate'

conflict_value="$(commitment_json trust-transition "$ALPHA_EVENT_HASH" "$ALPHA_CONFLICT_HASH")"
if invoke_commitment tt-audit-alpha-v1 peer0.alpha.audit.tenant-trust.test:7051 \
  "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt" "$conflict_value" >/tmp/conflict.out; then
  echo "Conflicting duplicate was unexpectedly accepted." >&2
  exit 1
fi
grep -q 'CONFLICTING_COMMITMENT' /tmp/conflict.out

invoke_commitment tt-audit-beta-v1 peer0.beta.audit.tenant-trust.test:7051 \
  "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt" "$beta_value" >/dev/null

platform_verifier
assert_query_value "$(query_commitment tt-audit-alpha-v1 trust-transition "$ALPHA_EVENT_HASH")" "$ALPHA_EVENT_HASH" "$ALPHA_COMMITMENT_HASH"
alpha_auditor
assert_query_value "$(query_commitment tt-audit-alpha-v1 trust-transition "$ALPHA_EVENT_HASH")" "$ALPHA_EVENT_HASH" "$ALPHA_COMMITMENT_HASH"
beta_auditor
assert_query_value "$(query_commitment tt-audit-beta-v1 access-decision "$BETA_EVENT_HASH")" "$BETA_EVENT_HASH" "$BETA_COMMITMENT_HASH"

platform_verifier
if query_commitment tt-audit-beta-v1 trust-transition "$ALPHA_EVENT_HASH" >/tmp/cross-channel.out; then
  echo "Alpha commitment was unexpectedly visible on the Beta channel." >&2
  exit 1
fi
grep -q 'COMMITMENT_NOT_FOUND' /tmp/cross-channel.out

platform_writer
if query_commitment tt-audit-alpha-v1 trust-transition "$ALPHA_EVENT_HASH" >/tmp/writer-query.out; then
  echo "Audit writer unexpectedly received query permission." >&2
  exit 1
fi
grep -q 'FORBIDDEN' /tmp/writer-query.out

alpha_auditor
if invoke_commitment tt-audit-alpha-v1 peer0.alpha.audit.tenant-trust.test:7051 \
  "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt" "$alpha_value" >/tmp/auditor-write.out; then
  echo "Tenant auditor unexpectedly received write permission." >&2
  exit 1
fi
grep -q 'FORBIDDEN' /tmp/auditor-write.out

rm -f /tmp/conflict.out /tmp/cross-channel.out /tmp/writer-query.out /tmp/auditor-write.out
echo "Audit chaincode verification passed: both definitions are committed, exact retries are idempotent, conflicts fail, roles are enforced and tenant channel state is isolated."
