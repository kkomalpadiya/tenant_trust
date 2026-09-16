BEGIN;

DO $verify_api_request_safeguard_schema$
BEGIN
  IF to_regclass('audit.api_sensitive_operation_receipts') IS NULL THEN
    RAISE EXCEPTION 'sensitive-operation receipt table is missing';
  END IF;
  IF NOT has_function_privilege(
    'tenant_trust_app',
    'audit.reserve_api_sensitive_operation(text,text,text,text,text,text)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'tenant runtime cannot execute the constrained replay guard';
  END IF;
  IF has_table_privilege('tenant_trust_app', 'audit.api_sensitive_operation_receipts', 'SELECT')
     OR has_table_privilege('tenant_trust_app', 'audit.api_sensitive_operation_receipts', 'INSERT')
     OR has_table_privilege('tenant_trust_app', 'audit.api_sensitive_operation_receipts', 'UPDATE')
     OR has_table_privilege('tenant_trust_app', 'audit.api_sensitive_operation_receipts', 'DELETE') THEN
    RAISE EXCEPTION 'tenant runtime has unsafe direct receipt-table privileges';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'audit'
      AND table_name = 'api_sensitive_operation_receipts'
      AND column_name IN ('idempotency_key', 'headers', 'body', 'payload', 'response_payload')
  ) THEN
    RAISE EXCEPTION 'receipt schema stores a raw key, request or response payload';
  END IF;
END
$verify_api_request_safeguard_schema$;

SET LOCAL ROLE tenant_trust_app;

DO $verify_sensitive_operation_replay$
DECLARE
  first_receipt record;
  replay_receipt record;
BEGIN
  SELECT * INTO STRICT first_receipt
  FROM audit.reserve_api_sensitive_operation(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'record:export',
    repeat('a', 64),
    repeat('b', 64),
    'op_018f1234-5678-7abc-8def-0123456789d1'
  );
  IF first_receipt.operation_id <> 'op_018f1234-5678-7abc-8def-0123456789d1'
     OR first_receipt.replayed THEN
    RAISE EXCEPTION 'first sensitive operation did not create its server identity';
  END IF;

  SELECT * INTO STRICT replay_receipt
  FROM audit.reserve_api_sensitive_operation(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'record:export',
    repeat('a', 64),
    repeat('b', 64),
    'op_018f1234-5678-7abc-8def-0123456789d2'
  );
  IF replay_receipt.operation_id <> first_receipt.operation_id
     OR NOT replay_receipt.replayed THEN
    RAISE EXCEPTION 'identical replay created a second operation identity';
  END IF;

  BEGIN
    PERFORM audit.reserve_api_sensitive_operation(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ac',
      'record:export',
      repeat('a', 64),
      repeat('c', 64),
      'op_018f1234-5678-7abc-8def-0123456789d3'
    );
    RAISE EXCEPTION 'conflicting idempotency reuse was accepted';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM <> 'SENSITIVE_OPERATION_IDEMPOTENCY_CONFLICT' THEN
      RAISE;
    END IF;
  END;

  BEGIN
    INSERT INTO audit.api_sensitive_operation_receipts (
      tenant_id, actor_subject_id, action, idempotency_key_hash_sha256,
      request_hash_sha256, operation_id
    ) VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ac',
      'tenant:admin', repeat('d', 64), repeat('e', 64),
      'op_018f1234-5678-7abc-8def-0123456789d4'
    );
    RAISE EXCEPTION 'tenant runtime inserted a receipt directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_sensitive_operation_replay$;

RESET ROLE;

DO $verify_sensitive_operation_receipt$
BEGIN
  IF (SELECT count(*) FROM audit.api_sensitive_operation_receipts
      WHERE idempotency_key_hash_sha256 = repeat('a', 64)) <> 1 THEN
    RAISE EXCEPTION 'replay guard retained an incorrect receipt count';
  END IF;

END
$verify_sensitive_operation_receipt$;

ROLLBACK;

SELECT 'API request safeguard verification passed' AS result;
