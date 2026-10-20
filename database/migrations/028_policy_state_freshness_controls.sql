CREATE FUNCTION identity.lock_current_actor_certificate_status(
  p_certificate_id identity.certificate_id,
  p_issuer_id identity.issuer_id,
  p_serial_number identity.x509_serial_number,
  p_fingerprint_sha256 identity.sha256_digest
)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  certificate_id identity.certificate_id,
  subject_id identity.subject_id,
  issuer_id identity.issuer_id,
  serial_number identity.x509_serial_number,
  fingerprint_sha256 identity.sha256_digest,
  state identity.certificate_state,
  not_before timestamptz,
  not_after timestamptz,
  version bigint,
  status_observed_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, identity
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
BEGIN
  IF v_tenant_id IS NULL
     OR v_subject_id IS NULL
     OR NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Certificate status lookup denied.';
  END IF;

  RETURN QUERY
  SELECT certificate.tenant_id, certificate.certificate_id, certificate.subject_id,
         certificate.issuer_id, certificate.serial_number, certificate.fingerprint_sha256,
         certificate.state, certificate.not_before, certificate.not_after,
         certificate.version, statement_timestamp()
  FROM identity.certificates AS certificate
  WHERE certificate.tenant_id = v_tenant_id
    AND certificate.subject_id = v_subject_id
    AND certificate.certificate_id = p_certificate_id
    AND certificate.issuer_id = p_issuer_id
    AND certificate.serial_number = p_serial_number
    AND certificate.fingerprint_sha256 = p_fingerprint_sha256
  LIMIT 1
  FOR SHARE;
END
$function$;

REVOKE ALL ON FUNCTION identity.lock_current_actor_certificate_status(
  identity.certificate_id, identity.issuer_id, identity.x509_serial_number, identity.sha256_digest
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.lock_current_actor_certificate_status(
  identity.certificate_id, identity.issuer_id, identity.x509_serial_number, identity.sha256_digest
) TO tenant_trust_app;

COMMENT ON FUNCTION identity.lock_current_actor_certificate_status(
  identity.certificate_id, identity.issuer_id, identity.x509_serial_number, identity.sha256_digest
) IS 'Returns and share-locks only the transaction-bound actor certificate so lifecycle changes serialize with protected requests';
