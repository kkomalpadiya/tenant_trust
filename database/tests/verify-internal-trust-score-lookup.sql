-- This verifier runs after the rolled-back trust-state and transition fixtures.

DO $verify_lookup_privileges$
BEGIN
  IF NOT has_function_privilege(
    'tenant_trust_app', 'trust.get_current_actor_trust_score()', 'EXECUTE'
  ) OR has_function_privilege(
    'tenant_trust_trust_engine', 'trust.get_current_actor_trust_score()', 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'internal trust-score lookup privileges are incorrect';
  END IF;
END
$verify_lookup_privileges$;

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_fresh_lookup$
DECLARE
  lookup record;
BEGIN
  BEGIN
    PERFORM 1 FROM trust.subject_trust_transitions;
    RAISE EXCEPTION 'application role read trust-transition storage directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  SELECT * INTO STRICT lookup FROM trust.get_current_actor_trust_score();
  IF lookup.tenant_id <> 'tnt_018f1234-5678-7abc-8def-0123456789ab'
     OR lookup.subject_id <> 'sub_018f1234-5678-7abc-8def-0123456789ab'
     OR lookup.freshness_state <> 'fresh'
     OR NOT lookup.usable_for_policy
     OR lookup.required_outcome IS NOT NULL
     OR lookup.reason_code IS NOT NULL
     OR lookup.policy_score <> 68.03
     OR lookup.policy_band <> 'medium'
     OR lookup.last_known_score <> lookup.policy_score
     OR lookup.age_seconds > lookup.stale_after_seconds
     OR lookup.transition_id <> 'trn_018f1234-5678-7abc-8def-0123456789f0'
     OR lookup.update_version <> 2
     OR lookup.model_version <> '1.0.0'
     OR lookup.configuration_version <> 1
     OR lookup.explanation_hash_sha256 IS NULL THEN
    RAISE EXCEPTION 'fresh policy lookup is incomplete or unsafe';
  END IF;
END
$verify_fresh_lookup$;

RESET ROLE;

-- Point to an older valid historical state solely to exercise the lookup's
-- stale branch. The surrounding transaction rolls this fixture back.
INSERT INTO trust.subject_trust_transitions (
  tenant_id, subject_id, transition_id, event_id, update_version,
  previous_transition_id, previous_score, previous_band, previous_recovery_streak,
  new_score, new_band, new_recovery_streak, weighted_score, smoothed_score,
  transition_kind, model_version, configuration_version, observed_at, evaluated_at,
  explanation_json, explanation_hash_sha256, recorded_at
) VALUES (
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'trn_018f1234-5678-7abc-8def-0123456789f2',
  'evt_018f1234-5678-7abc-8def-0123456789f2',
  1, NULL, 60, 'uninitialized', 0, 50, 'medium', 0, 50, 50, 'held',
  '1.0.0', 1,
  TIMESTAMPTZ '2026-10-06 08:00:00+00',
  TIMESTAMPTZ '2026-10-06 08:00:01+00',
  '{}'::jsonb::text, repeat('c', 64), clock_timestamp()
);

UPDATE trust.subject_trust_transition_current
SET transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f2',
    update_version = 1,
    updated_at = clock_timestamp()
WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
  AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab';

SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $verify_stale_lookup$
DECLARE
  lookup record;
BEGIN
  SELECT * INTO STRICT lookup FROM trust.get_current_actor_trust_score();
  IF lookup.freshness_state <> 'stale'
     OR lookup.usable_for_policy
     OR lookup.required_outcome <> 'DENY'
     OR lookup.reason_code <> 'TRUST_STATE_STALE'
     OR lookup.policy_score IS NOT NULL
     OR lookup.policy_band IS NOT NULL
     OR lookup.last_known_score <> 50
     OR lookup.last_known_band <> 'medium'
     OR lookup.age_seconds <= lookup.stale_after_seconds
     OR lookup.update_version <> 1 THEN
    RAISE EXCEPTION 'stale policy lookup did not fail closed';
  END IF;
END
$verify_stale_lookup$;

SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ad'
);

DO $verify_missing_and_tenant_bound_lookup$
DECLARE
  lookup record;
BEGIN
  SELECT * INTO STRICT lookup FROM trust.get_current_actor_trust_score();
  IF lookup.tenant_id <> 'tnt_018f1234-5678-7abc-8def-0123456789ac'
     OR lookup.subject_id <> 'sub_018f1234-5678-7abc-8def-0123456789ad'
     OR lookup.freshness_state <> 'missing'
     OR lookup.usable_for_policy
     OR lookup.required_outcome <> 'DENY'
     OR lookup.reason_code <> 'TRUST_STATE_MISSING'
     OR lookup.policy_score IS NOT NULL
     OR lookup.last_known_score IS NOT NULL
     OR lookup.age_seconds IS NOT NULL
     OR lookup.transition_id IS NOT NULL
     OR lookup.model_version IS NOT NULL
     OR lookup.configuration_version IS NOT NULL THEN
    RAISE EXCEPTION 'missing or transaction-bound lookup is incorrect';
  END IF;
END
$verify_missing_and_tenant_bound_lookup$;

RESET ROLE;

DO $verify_lookup_requires_context$
BEGIN
  PERFORM set_config('tenant_trust.tenant_id', '', true);
  PERFORM set_config('tenant_trust.subject_id', '', true);
  SET LOCAL ROLE tenant_trust_app;
  BEGIN
    PERFORM trust.get_current_actor_trust_score();
    RAISE EXCEPTION 'lookup without an actor context was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RESET ROLE;
END
$verify_lookup_requires_context$;

\echo 'Verified current-actor trust lookup freshness, conservative denial and tenant binding.'
