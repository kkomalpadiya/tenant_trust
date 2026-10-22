#!/bin/sh
set -eu

FABRIC_ROOT=/fabric
CHAINCODE_NAME=tenant-trust-audit
PLATFORM_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/platform.audit.tenant-trust.test"
ALPHA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/alpha.audit.tenant-trust.test"
BETA_ROOT="$FABRIC_ROOT/organizations/peerOrganizations/beta.audit.tenant-trust.test"
ALPHA_EVENT_HASH=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ALPHA_COMMITMENT_HASH=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
BETA_EVENT_HASH=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
BETA_COMMITMENT_HASH=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

use_identity() {
  export CORE_PEER_ADDRESS="$1"
  export CORE_PEER_LOCALMSPID="$2"
  export CORE_PEER_MSPCONFIGPATH="$3"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_TLS_ROOTCERT_FILE="$4"
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

alpha_auditor_on_beta_peer() {
  use_identity peer0.beta.audit.tenant-trust.test:7051 TenantAlphaAuditMSP \
    "$ALPHA_ROOT/users/tenant-auditor@alpha.audit.tenant-trust.test/msp" \
    "$BETA_ROOT/peers/peer0.beta.audit.tenant-trust.test/tls/ca.crt"
}

beta_auditor_on_alpha_peer() {
  use_identity peer0.alpha.audit.tenant-trust.test:7051 TenantBetaAuditMSP \
    "$BETA_ROOT/users/tenant-auditor@beta.audit.tenant-trust.test/msp" \
    "$ALPHA_ROOT/peers/peer0.alpha.audit.tenant-trust.test/tls/ca.crt"
}

query_commitment() {
  invocation="$(jq -cn --arg record_type "$2" --arg event_hash "$3" '{function:"TenantTrustAudit:ReadCommitment",Args:[$record_type,$event_hash]}')"
  peer chaincode query -C "$1" -n "$CHAINCODE_NAME" -c "$invocation" 2>&1
}

assert_minimal_value() {
  printf '%s' "$1" | jq -e --arg event_hash "$2" --arg commitment_hash "$3" \
    '.eventKeyHashSha256 == $event_hash and .commitmentHashSha256 == $commitment_hash and length == 6
     and has("tenantId") == false and has("subjectId") == false and has("eventId") == false
     and has("payload") == false and has("decisionId") == false and has("certificateId") == false' >/dev/null
}

alpha_auditor
assert_minimal_value "$(query_commitment tt-audit-alpha-v1 trust-transition "$ALPHA_EVENT_HASH")" \
  "$ALPHA_EVENT_HASH" "$ALPHA_COMMITMENT_HASH"
beta_auditor
assert_minimal_value "$(query_commitment tt-audit-beta-v1 access-decision "$BETA_EVENT_HASH")" \
  "$BETA_EVENT_HASH" "$BETA_COMMITMENT_HASH"

platform_verifier
if query_commitment tt-audit-beta-v1 trust-transition "$ALPHA_EVENT_HASH" >/tmp/alpha-state-on-beta.out; then
  echo "Alpha commitment was unexpectedly present on the Beta ledger." >&2
  exit 1
fi
grep -q 'COMMITMENT_NOT_FOUND' /tmp/alpha-state-on-beta.out
if query_commitment tt-audit-alpha-v1 access-decision "$BETA_EVENT_HASH" >/tmp/beta-state-on-alpha.out; then
  echo "Beta commitment was unexpectedly present on the Alpha ledger." >&2
  exit 1
fi
grep -q 'COMMITMENT_NOT_FOUND' /tmp/beta-state-on-alpha.out

alpha_auditor_on_beta_peer
if query_commitment tt-audit-beta-v1 access-decision "$BETA_EVENT_HASH" >/tmp/alpha-auditor-on-beta.out; then
  echo "Alpha tenant auditor unexpectedly queried the Beta ledger." >&2
  exit 1
fi
if grep -q "$BETA_COMMITMENT_HASH" /tmp/alpha-auditor-on-beta.out; then
  echo "Rejected Alpha auditor query leaked the Beta commitment value." >&2
  exit 1
fi

beta_auditor_on_alpha_peer
if query_commitment tt-audit-alpha-v1 trust-transition "$ALPHA_EVENT_HASH" >/tmp/beta-auditor-on-alpha.out; then
  echo "Beta tenant auditor unexpectedly queried the Alpha ledger." >&2
  exit 1
fi
if grep -q "$ALPHA_COMMITMENT_HASH" /tmp/beta-auditor-on-alpha.out; then
  echo "Rejected Beta auditor query leaked the Alpha commitment value." >&2
  exit 1
fi

rm -f /tmp/alpha-state-on-beta.out /tmp/beta-state-on-alpha.out \
  /tmp/alpha-auditor-on-beta.out /tmp/beta-auditor-on-alpha.out
echo "Ledger privacy verification passed: tenant auditors read only their own channel, cross-channel state is absent, rejected queries leak no commitment, and public values contain only six approved fields."
