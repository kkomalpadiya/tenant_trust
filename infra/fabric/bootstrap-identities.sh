#!/bin/sh
set -eu

FABRIC_ROOT=/fabric
ORGANIZATIONS="$FABRIC_ROOT/organizations"
MARKER="$ORGANIZATIONS/.fabric-ca-identities-v1"
MSP_TEMPLATE=/scripts/msp-config.yaml

if [ -f "$MARKER" ]; then
  echo "Fabric CA identities already exist; preserving enrolled material."
  exit 0
fi

wait_for_ca() {
  ca_name="$1"
  ca_host="$2"
  ca_cert="$3"
  attempt=1
  while [ "$attempt" -le 30 ]; do
    if FABRIC_CA_CLIENT_HOME=/tmp/fabric-ca-health fabric-ca-client getcainfo \
      -u "https://$ca_host:7054" \
      --caname "$ca_name" \
      --tls.certfiles "$ca_cert" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  echo "Timed out waiting for $ca_name at $ca_host." >&2
  exit 1
}

normalize_msp() {
  msp_dir="$1"
  set -- "$msp_dir"/cacerts/*
  ca_source="$1"
  cp "$ca_source" "$msp_dir/.ca-cert.pem.tmp"
  rm -f "$msp_dir"/cacerts/*
  mv "$msp_dir/.ca-cert.pem.tmp" "$msp_dir/cacerts/ca-cert.pem"
  cp "$MSP_TEMPLATE" "$msp_dir/config.yaml"
}

enroll_identity() {
  ca_name="$1"
  ca_host="$2"
  ca_cert="$3"
  enrollment_id="$4"
  enrollment_secret="$5"
  msp_dir="$6"
  shift 6
  FABRIC_CA_CLIENT_HOME=/tmp/fabric-ca-client fabric-ca-client enroll \
    -u "https://$enrollment_id:$enrollment_secret@$ca_host:7054" \
    --caname "$ca_name" \
    --mspdir "$msp_dir" \
    --tls.certfiles "$ca_cert" \
    "$@"
  normalize_msp "$msp_dir"
}

enroll_tls() {
  ca_name="$1"
  ca_host="$2"
  ca_cert="$3"
  enrollment_id="$4"
  enrollment_secret="$5"
  tls_dir="$6"
  csr_hosts="$7"
  FABRIC_CA_CLIENT_HOME=/tmp/fabric-ca-client fabric-ca-client enroll \
    -u "https://$enrollment_id:$enrollment_secret@$ca_host:7054" \
    --caname "$ca_name" \
    --mspdir "$tls_dir" \
    --enrollment.profile tls \
    --csr.hosts "$csr_hosts" \
    --tls.certfiles "$ca_cert"
  set -- "$tls_dir"/tlscacerts/*
  cp "$1" "$tls_dir/ca.crt"
  set -- "$tls_dir"/signcerts/*
  cp "$1" "$tls_dir/server.crt"
  set -- "$tls_dir"/keystore/*
  cp "$1" "$tls_dir/server.key"
}

register_identity() {
  admin_home="$1"
  ca_name="$2"
  ca_host="$3"
  ca_cert="$4"
  enrollment_id="$5"
  enrollment_secret="$6"
  identity_type="$7"
  identity_attrs="${8:-}"
  if [ -n "$identity_attrs" ]; then
    FABRIC_CA_CLIENT_HOME="$admin_home" fabric-ca-client register \
      -u "https://$ca_host:7054" \
      --caname "$ca_name" \
      --id.name "$enrollment_id" \
      --id.secret "$enrollment_secret" \
      --id.type "$identity_type" \
      --id.attrs "$identity_attrs" \
      --tls.certfiles "$ca_cert" >/dev/null
  else
    FABRIC_CA_CLIENT_HOME="$admin_home" fabric-ca-client register \
      -u "https://$ca_host:7054" \
      --caname "$ca_name" \
      --id.name "$enrollment_id" \
      --id.secret "$enrollment_secret" \
      --id.type "$identity_type" \
      --tls.certfiles "$ca_cert" >/dev/null
  fi
}

create_org_msp() {
  admin_msp="$1"
  org_msp="$2"
  tls_dir="$3"
  mkdir -p "$org_msp/cacerts" "$org_msp/tlscacerts"
  cp "$admin_msp/cacerts/ca-cert.pem" "$org_msp/cacerts/ca-cert.pem"
  cp "$tls_dir/ca.crt" "$org_msp/tlscacerts/tlsca-cert.pem"
  cp "$MSP_TEMPLATE" "$org_msp/config.yaml"
}

ORDERER_CA_CERT="$FABRIC_ROOT/ca/orderer/ca-cert.pem"
PLATFORM_CA_CERT="$FABRIC_ROOT/ca/platform/ca-cert.pem"
ALPHA_CA_CERT="$FABRIC_ROOT/ca/alpha/ca-cert.pem"
BETA_CA_CERT="$FABRIC_ROOT/ca/beta/ca-cert.pem"

wait_for_ca ca-orderer ca-orderer "$ORDERER_CA_CERT"
wait_for_ca ca-platform ca-platform "$PLATFORM_CA_CERT"
wait_for_ca ca-alpha ca-alpha "$ALPHA_CA_CERT"
wait_for_ca ca-beta ca-beta "$BETA_CA_CERT"

ORDERER_DOMAIN=audit.tenant-trust.test
ORDERER_ROOT="$ORGANIZATIONS/ordererOrganizations/$ORDERER_DOMAIN"
ORDERER_ADMIN_HOME="$ORDERER_ROOT/ca-admin"
enroll_identity ca-orderer ca-orderer "$ORDERER_CA_CERT" admin "$FABRIC_CA_ORDERER_ADMIN_PASSWORD" "$ORDERER_ADMIN_HOME/msp"
register_identity "$ORDERER_ADMIN_HOME" ca-orderer ca-orderer "$ORDERER_CA_CERT" orderer0 "$FABRIC_ORDERER_SECRET" orderer
register_identity "$ORDERER_ADMIN_HOME" ca-orderer ca-orderer "$ORDERER_CA_CERT" orderer-admin "$FABRIC_ORDERER_ORG_ADMIN_SECRET" admin "tenantTrust.role=fabric-admin:ecert"
ORDERER_NODE="$ORDERER_ROOT/orderers/orderer0.$ORDERER_DOMAIN"
enroll_identity ca-orderer ca-orderer "$ORDERER_CA_CERT" orderer0 "$FABRIC_ORDERER_SECRET" "$ORDERER_NODE/msp" --csr.hosts "orderer0.$ORDERER_DOMAIN"
enroll_tls ca-orderer ca-orderer "$ORDERER_CA_CERT" orderer0 "$FABRIC_ORDERER_SECRET" "$ORDERER_NODE/tls" "orderer0.$ORDERER_DOMAIN,localhost"
enroll_identity ca-orderer ca-orderer "$ORDERER_CA_CERT" orderer-admin "$FABRIC_ORDERER_ORG_ADMIN_SECRET" "$ORDERER_ROOT/users/Admin@$ORDERER_DOMAIN/msp"
create_org_msp "$ORDERER_ROOT/users/Admin@$ORDERER_DOMAIN/msp" "$ORDERER_ROOT/msp" "$ORDERER_NODE/tls"

create_peer_org() {
  ca_name="$1"
  ca_host="$2"
  ca_cert="$3"
  domain="$4"
  peer_id="$5"
  peer_secret="$6"
  admin_secret="$7"
  auditor_secret="$8"

  org_root="$ORGANIZATIONS/peerOrganizations/$domain"
  admin_home="$org_root/ca-admin"
  peer_host="peer0.$domain"
  enroll_identity "$ca_name" "$ca_host" "$ca_cert" admin "$9" "$admin_home/msp"
  register_identity "$admin_home" "$ca_name" "$ca_host" "$ca_cert" "$peer_id" "$peer_secret" peer
  register_identity "$admin_home" "$ca_name" "$ca_host" "$ca_cert" org-admin "$admin_secret" admin "tenantTrust.role=fabric-admin:ecert"
  register_identity "$admin_home" "$ca_name" "$ca_host" "$ca_cert" tenant-auditor "$auditor_secret" client "tenantTrust.role=tenant-auditor:ecert"
  enroll_identity "$ca_name" "$ca_host" "$ca_cert" "$peer_id" "$peer_secret" "$org_root/peers/$peer_host/msp" --csr.hosts "$peer_host"
  enroll_tls "$ca_name" "$ca_host" "$ca_cert" "$peer_id" "$peer_secret" "$org_root/peers/$peer_host/tls" "$peer_host,localhost"
  enroll_identity "$ca_name" "$ca_host" "$ca_cert" org-admin "$admin_secret" "$org_root/users/Admin@$domain/msp"
  enroll_identity "$ca_name" "$ca_host" "$ca_cert" tenant-auditor "$auditor_secret" "$org_root/users/tenant-auditor@$domain/msp"
  create_org_msp "$org_root/users/Admin@$domain/msp" "$org_root/msp" "$org_root/peers/$peer_host/tls"
}

PLATFORM_DOMAIN=platform.audit.tenant-trust.test
PLATFORM_ROOT="$ORGANIZATIONS/peerOrganizations/$PLATFORM_DOMAIN"
PLATFORM_ADMIN_HOME="$PLATFORM_ROOT/ca-admin"
enroll_identity ca-platform ca-platform "$PLATFORM_CA_CERT" admin "$FABRIC_CA_PLATFORM_ADMIN_PASSWORD" "$PLATFORM_ADMIN_HOME/msp"
register_identity "$PLATFORM_ADMIN_HOME" ca-platform ca-platform "$PLATFORM_CA_CERT" peer0 "$FABRIC_PLATFORM_PEER_SECRET" peer
register_identity "$PLATFORM_ADMIN_HOME" ca-platform ca-platform "$PLATFORM_CA_CERT" org-admin "$FABRIC_PLATFORM_ORG_ADMIN_SECRET" admin "tenantTrust.role=fabric-admin:ecert"
register_identity "$PLATFORM_ADMIN_HOME" ca-platform ca-platform "$PLATFORM_CA_CERT" audit-writer "$FABRIC_AUDIT_WRITER_SECRET" client "tenantTrust.role=audit-writer:ecert"
register_identity "$PLATFORM_ADMIN_HOME" ca-platform ca-platform "$PLATFORM_CA_CERT" audit-verifier "$FABRIC_AUDIT_VERIFIER_SECRET" client "tenantTrust.role=audit-verifier:ecert"
register_identity "$PLATFORM_ADMIN_HOME" ca-platform ca-platform "$PLATFORM_CA_CERT" audit-commit-listener "$FABRIC_AUDIT_LISTENER_SECRET" client "tenantTrust.role=audit-commit-listener:ecert"
PLATFORM_PEER="$PLATFORM_ROOT/peers/peer0.$PLATFORM_DOMAIN"
enroll_identity ca-platform ca-platform "$PLATFORM_CA_CERT" peer0 "$FABRIC_PLATFORM_PEER_SECRET" "$PLATFORM_PEER/msp" --csr.hosts "peer0.$PLATFORM_DOMAIN"
enroll_tls ca-platform ca-platform "$PLATFORM_CA_CERT" peer0 "$FABRIC_PLATFORM_PEER_SECRET" "$PLATFORM_PEER/tls" "peer0.$PLATFORM_DOMAIN,localhost"
enroll_identity ca-platform ca-platform "$PLATFORM_CA_CERT" org-admin "$FABRIC_PLATFORM_ORG_ADMIN_SECRET" "$PLATFORM_ROOT/users/Admin@$PLATFORM_DOMAIN/msp"
enroll_identity ca-platform ca-platform "$PLATFORM_CA_CERT" audit-writer "$FABRIC_AUDIT_WRITER_SECRET" "$PLATFORM_ROOT/users/audit-writer@$PLATFORM_DOMAIN/msp"
enroll_identity ca-platform ca-platform "$PLATFORM_CA_CERT" audit-verifier "$FABRIC_AUDIT_VERIFIER_SECRET" "$PLATFORM_ROOT/users/audit-verifier@$PLATFORM_DOMAIN/msp"
enroll_identity ca-platform ca-platform "$PLATFORM_CA_CERT" audit-commit-listener "$FABRIC_AUDIT_LISTENER_SECRET" "$PLATFORM_ROOT/users/audit-commit-listener@$PLATFORM_DOMAIN/msp"
create_org_msp "$PLATFORM_ROOT/users/Admin@$PLATFORM_DOMAIN/msp" "$PLATFORM_ROOT/msp" "$PLATFORM_PEER/tls"

create_peer_org ca-alpha ca-alpha "$ALPHA_CA_CERT" alpha.audit.tenant-trust.test peer0 "$FABRIC_ALPHA_PEER_SECRET" "$FABRIC_ALPHA_ORG_ADMIN_SECRET" "$FABRIC_ALPHA_AUDITOR_SECRET" "$FABRIC_CA_ALPHA_ADMIN_PASSWORD"
create_peer_org ca-beta ca-beta "$BETA_CA_CERT" beta.audit.tenant-trust.test peer0 "$FABRIC_BETA_PEER_SECRET" "$FABRIC_BETA_ORG_ADMIN_SECRET" "$FABRIC_BETA_AUDITOR_SECRET" "$FABRIC_CA_BETA_ADMIN_PASSWORD"

touch "$MARKER"
echo "Enrolled distinct Fabric CA identities under runtime/fabric."
