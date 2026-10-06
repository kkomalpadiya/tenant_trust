\set ON_ERROR_STOP on

BEGIN;

INSERT INTO trust.evidence_sources (
  tenant_id, source_id, issuer_id, source_name, evidence_type,
  state, verification_algorithm, maximum_age_seconds, synthetic
) VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789e0', NULL,
   'alpha-flood-verifier', 'identity', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789e1', NULL,
   'alpha-independent-verifier', 'identity', 'planned', 'ed25519', 300, true);

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
SELECT * FROM trust.enroll_evidence_source(
  'src_018f1234-5678-7abc-8def-0123456789e0',
  'key_018f1234-5678-7abc-8def-0123456789e0',
  'xTDFvh5FOfldrRPRPrV1n_LmzQQdLuIOwIs9J61tjbQ', transaction_timestamp()
);
SELECT * FROM trust.enroll_evidence_source(
  'src_018f1234-5678-7abc-8def-0123456789e1',
  'key_018f1234-5678-7abc-8def-0123456789e1',
  'Fr7WOdZpT6Nq7kq9vd1de9HmD6k7K4IYXjLLO38rrh0', transaction_timestamp()
);
SELECT * FROM trust.configure_evidence_source_safeguards(
  'src_018f1234-5678-7abc-8def-0123456789e0', 60, 2, 2, 0.1000, transaction_timestamp()
);

DO $registry_bypass$
BEGIN
  BEGIN
    UPDATE trust.evidence_sources
    SET maximum_influence = 0.9000
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789e0';
    RAISE EXCEPTION 'Direct safeguard mutation unexpectedly succeeded.';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$registry_bypass$;

DO $cross_tenant$
BEGIN
  PERFORM identity.set_tenant_actor_context(
    'tnt_018f1234-5678-7abc-8def-0123456789ac',
    'sub_018f1234-5678-7abc-8def-0123456789ae'
  );
  BEGIN
    PERFORM trust.configure_evidence_source_safeguards(
      'src_018f1234-5678-7abc-8def-0123456789e0', 60, 100, 10, 0.9000, transaction_timestamp()
    );
    RAISE EXCEPTION 'Cross-tenant safeguard configuration unexpectedly succeeded.';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$cross_tenant$;

SELECT set_config('tenant_trust.tenant_id', '', true);
SELECT set_config('tenant_trust.subject_id', '', true);

DO $flood$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_decision record;
  v_index integer;
BEGIN
  FOR v_index IN 0..3 LOOP
    SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'src_018f1234-5678-7abc-8def-0123456789e0',
      'key_018f1234-5678-7abc-8def-0123456789e0',
      'identity', ('evt_018f1234-5678-7abc-8def-0123456789f' || v_index)::trust.evidence_event_id,
      v_index + 1, repeat(chr(65 + v_index), 22),
      v_now - interval '1 second', v_now + interval '299 seconds', repeat(v_index::text, 64), true
    );
    IF v_index < 2 AND NOT v_decision.accepted THEN
      RAISE EXCEPTION 'In-quota evidence % was rejected.', v_index;
    END IF;
    IF v_index >= 2 AND v_decision.reason_code <> 'EVIDENCE_RATE_LIMITED' THEN
      RAISE EXCEPTION 'Over-quota evidence % was not rate limited.', v_index;
    END IF;
  END LOOP;

  SELECT * INTO v_decision FROM trust.apply_evidence_replay_guard(
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'src_018f1234-5678-7abc-8def-0123456789e1',
    'key_018f1234-5678-7abc-8def-0123456789e1',
    'identity', 'evt_018f1234-5678-7abc-8def-0123456789f4', 1,
    'EEEEEEEEEEEEEEEEEEEEEE', v_now - interval '1 second', v_now + interval '299 seconds', repeat('e', 64), true
  );
  IF NOT v_decision.accepted THEN
    RAISE EXCEPTION 'An independent source was affected by the noisy source quota.';
  END IF;
END
$flood$;

RESET ROLE;

DO $verification$
BEGIN
  IF (SELECT state FROM trust.evidence_sources
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND source_id = 'src_018f1234-5678-7abc-8def-0123456789e0') <> 'suspended' THEN
    RAISE EXCEPTION 'Repeated rate-limit violations did not suspend the noisy source.';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM trust.evidence_source_rate_state
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND source_id = 'src_018f1234-5678-7abc-8def-0123456789e0'
      AND accepted_count = 2 AND rate_limited_count = 2
  ) THEN
    RAISE EXCEPTION 'Per-source fixed-window counters are incorrect.';
  END IF;
  IF (SELECT count(*) FROM trust.evidence_ingestion_receipts
      WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789e0'
        AND maximum_source_influence = 0.1000) <> 2 THEN
    RAISE EXCEPTION 'Accepted evidence did not snapshot the source influence cap.';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM trust.evidence_source_control_events
    WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789e0'
      AND event_type = 'automatically_suspended'
      AND reason_code = 'RATE_LIMIT_THRESHOLD_REACHED'
  ) THEN
    RAISE EXCEPTION 'Automatic source suspension was not audited.';
  END IF;
  IF has_table_privilege('tenant_trust_app', 'trust.evidence_source_rate_state', 'SELECT')
    OR has_table_privilege('tenant_trust_app', 'trust.evidence_source_control_events', 'UPDATE') THEN
    RAISE EXCEPTION 'Application role received direct safeguard-state access.';
  END IF;
END
$verification$;

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);
SELECT * FROM trust.set_evidence_source_suspension(
  'src_018f1234-5678-7abc-8def-0123456789e0', false, 'SOURCE_REVIEWED', transaction_timestamp()
);

DO $resumed$
BEGIN
  IF (SELECT state FROM trust.evidence_sources
      WHERE source_id = 'src_018f1234-5678-7abc-8def-0123456789e0') <> 'active' THEN
    RAISE EXCEPTION 'Tenant administrator could not resume a reviewed source.';
  END IF;
END
$resumed$;

ROLLBACK;

SELECT 'PASS source quotas are tenant scoped and isolate independent evidence sources' AS result;
SELECT 'PASS repeated rate-limit violations suspend a noisy source with append-only audit history' AS result;
SELECT 'PASS accepted evidence snapshots the lesser tenant and source influence cap' AS result;
