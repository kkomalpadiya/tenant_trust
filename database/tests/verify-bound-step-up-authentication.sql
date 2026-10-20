\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $bound_step_up$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_count integer;
BEGIN
  PERFORM identity.enroll_step_up_factor(
    'suf_018f1234-5678-7abc-8def-0123456789d1',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    v_now
  );
  PERFORM audit.issue_step_up_challenge(
    'suc_018f1234-5678-7abc-8def-0123456789d2',
    'suf_018f1234-5678-7abc-8def-0123456789d1',
    'record:export',
    'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
    repeat('a', 64),
    v_now,
    v_now + interval '120 seconds'
  );
  SELECT count(*) INTO v_count
  FROM audit.get_step_up_challenge('suc_018f1234-5678-7abc-8def-0123456789d2');
  IF v_count <> 1 THEN RAISE EXCEPTION 'bound challenge was not available once'; END IF;

  PERFORM audit.complete_step_up_challenge(
    'suc_018f1234-5678-7abc-8def-0123456789d2',
    repeat('b', 64),
    v_now + interval '1 second',
    v_now + interval '301 seconds'
  );

  SELECT count(*) INTO v_count FROM audit.consume_step_up_proof(
    repeat('b', 64), repeat('a', 64), 'tenant:admin',
    'req_018f1234-5678-7abc-8def-0123456789d3', v_now + interval '2 seconds'
  );
  IF v_count <> 0 THEN RAISE EXCEPTION 'proof crossed its action binding'; END IF;

  SELECT count(*) INTO v_count FROM audit.consume_step_up_proof(
    repeat('b', 64), repeat('c', 64), 'record:export',
    'req_018f1234-5678-7abc-8def-0123456789d4', v_now + interval '2 seconds'
  );
  IF v_count <> 0 THEN RAISE EXCEPTION 'proof crossed its session binding'; END IF;

  SELECT count(*) INTO v_count FROM audit.consume_step_up_proof(
    repeat('b', 64), repeat('a', 64), 'record:export',
    'req_018f1234-5678-7abc-8def-0123456789d5', v_now + interval '2 seconds'
  );
  IF v_count <> 1 THEN RAISE EXCEPTION 'valid proof was not consumed'; END IF;

  SELECT count(*) INTO v_count FROM audit.consume_step_up_proof(
    repeat('b', 64), repeat('a', 64), 'record:export',
    'req_018f1234-5678-7abc-8def-0123456789d6', v_now + interval '2 seconds'
  );
  IF v_count <> 0 THEN RAISE EXCEPTION 'single-use proof was replayed'; END IF;
END
$bound_step_up$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ae'
);

DO $cross_tenant_denied$
DECLARE v_count integer;
BEGIN
  SELECT count(*) INTO v_count FROM audit.consume_step_up_proof(
    repeat('b', 64), repeat('a', 64), 'record:export',
    'req_018f1234-5678-7abc-8def-0123456789d7', clock_timestamp()
  );
  IF v_count <> 0 THEN RAISE EXCEPTION 'proof crossed its tenant or subject binding'; END IF;
END
$cross_tenant_denied$;

ROLLBACK;
\echo 'Verified tenant, subject, action and session binding plus atomic single-use consumption.'
