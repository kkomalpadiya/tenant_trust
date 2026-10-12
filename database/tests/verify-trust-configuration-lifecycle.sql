\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $member_denied$
BEGIN
  BEGIN
    PERFORM trust.create_trust_configuration_draft(
      '1.1.0', 62, 0.35, 0.20, 2700,
      0.20, 0.25, 0.25, 0.15, 0.15,
      'MEMBER_PROBE', clock_timestamp()
    );
    RAISE EXCEPTION 'ordinary member created a trust configuration draft';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM trust.list_trust_configuration_history();
    RAISE EXCEPTION 'ordinary member read trust configuration history';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$member_denied$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $invalid_inputs_and_direct_bypass$
BEGIN
  BEGIN
    PERFORM trust.create_trust_configuration_draft(
      '1.1.0', 62, 0, 0.20, 2700,
      0.20, 0.25, 0.25, 0.15, 0.15,
      'INVALID_ALPHA', clock_timestamp()
    );
    RAISE EXCEPTION 'zero smoothing alpha was accepted';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;

  BEGIN
    PERFORM trust.create_trust_configuration_draft(
      '1.1.0', 62, 0.35, 0.20, 2700,
      0.20, 0.25, 0.25, 0.15, 0.14,
      'INVALID_WEIGHTS', clock_timestamp()
    );
    RAISE EXCEPTION 'non-unit trust weights were accepted';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;

  BEGIN
    INSERT INTO trust.trust_configurations (
      tenant_id, configuration_version, model_version, state, initial_score,
      smoothing_alpha, maximum_source_influence, stale_after_seconds,
      identity_weight, device_weight, behaviour_weight, certificate_weight,
      compliance_weight, created_by_subject_id
    ) VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab', 99, '9.9.9', 'draft', 50,
      0.50, 0.50, 60, 0.20, 0.25, 0.25, 0.15, 0.15,
      'sub_018f1234-5678-7abc-8def-0123456789ac'
    );
    RAISE EXCEPTION 'tenant runtime inserted a trust configuration directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$invalid_inputs_and_direct_bypass$;

SELECT * FROM trust.create_trust_configuration_draft(
  '1.1.0', 62, 0.35, 0.20, 2700,
  0.10, 0.20, 0.30, 0.25, 0.15,
  'MODEL_TUNING', clock_timestamp()
);

DO $draft_created$
BEGIN
  IF (SELECT count(*) FROM trust.list_trust_configuration_history()) <> 2
     OR NOT EXISTS (
       SELECT 1 FROM trust.list_trust_configuration_history()
       WHERE configuration_version = 2
         AND state = 'draft'
         AND model_version = '1.1.0'
         AND latest_event_type = 'draft_created'
         AND latest_reason_code = 'MODEL_TUNING'
         AND previous_active_configuration_version = 1
     ) THEN
    RAISE EXCEPTION 'validated draft and its history event were not recorded';
  END IF;
END
$draft_created$;

SELECT * FROM trust.activate_trust_configuration(
  2, 'ACTIVATE_MODEL', clock_timestamp()
);

DO $activation_is_atomic$
BEGIN
  IF (SELECT count(*) FROM trust.trust_configurations WHERE state = 'active') <> 1
     OR NOT EXISTS (
       SELECT 1 FROM trust.trust_configurations
       WHERE configuration_version = 1 AND state = 'superseded'
     )
     OR NOT EXISTS (
       SELECT 1 FROM trust.list_trust_configuration_history()
       WHERE configuration_version = 2
         AND state = 'active'
         AND latest_event_type = 'activated'
         AND previous_active_configuration_version = 1
     ) THEN
    RAISE EXCEPTION 'draft activation did not atomically supersede the prior version';
  END IF;
END
$activation_is_atomic$;

SELECT * FROM trust.rollback_trust_configuration(
  1, 'RESTORE_BASELINE', clock_timestamp()
);

DO $rollback_appends_new_version$
BEGIN
  IF (SELECT count(*) FROM trust.trust_configurations) <> 3
     OR (SELECT count(*) FROM trust.trust_configurations WHERE state = 'active') <> 1
     OR NOT EXISTS (
       SELECT 1
       FROM trust.trust_configurations AS restored
       JOIN trust.trust_configurations AS baseline
         ON baseline.tenant_id = restored.tenant_id
        AND baseline.configuration_version = 1
       WHERE restored.configuration_version = 3
         AND restored.state = 'active'
         AND baseline.state = 'superseded'
         AND restored.model_version = baseline.model_version
         AND restored.initial_score = baseline.initial_score
         AND restored.smoothing_alpha = baseline.smoothing_alpha
         AND restored.maximum_source_influence = baseline.maximum_source_influence
         AND restored.stale_after_seconds = baseline.stale_after_seconds
         AND restored.identity_weight = baseline.identity_weight
         AND restored.device_weight = baseline.device_weight
         AND restored.behaviour_weight = baseline.behaviour_weight
         AND restored.certificate_weight = baseline.certificate_weight
         AND restored.compliance_weight = baseline.compliance_weight
     )
     OR NOT EXISTS (
       SELECT 1 FROM trust.list_trust_configuration_history()
       WHERE configuration_version = 3
         AND latest_event_type = 'rollback_activated'
         AND previous_active_configuration_version = 2
         AND rollback_target_configuration_version = 1
         AND latest_reason_code = 'RESTORE_BASELINE'
     ) THEN
    RAISE EXCEPTION 'rollback did not append and activate a copy of the historical target';
  END IF;

  BEGIN
    PERFORM trust.rollback_trust_configuration(3, 'INVALID_CURRENT_TARGET', clock_timestamp());
    RAISE EXCEPTION 'rollback accepted the current active version as a historical target';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$rollback_appends_new_version$;

RESET ROLE;

DO $history_is_append_only_and_tenant_isolated$
BEGIN
  IF (SELECT count(*) FROM trust.trust_configuration_events
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab') <> 3 THEN
    RAISE EXCEPTION 'trust configuration lifecycle events are incomplete';
  END IF;
  IF (SELECT count(*) FROM trust.trust_configurations
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac') <> 1
     OR NOT EXISTS (
       SELECT 1 FROM trust.trust_configurations
       WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ac'
         AND configuration_version = 1 AND state = 'active'
     ) THEN
    RAISE EXCEPTION 'Alpha configuration changes contaminated Beta';
  END IF;

  BEGIN
    UPDATE trust.trust_configurations
    SET initial_score = 99
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND configuration_version = 1;
    RAISE EXCEPTION 'historical trust configuration content was rewritten';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    DELETE FROM trust.trust_configurations
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND configuration_version = 1;
    RAISE EXCEPTION 'historical trust configuration was deleted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    DELETE FROM trust.trust_configuration_events
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';
    RAISE EXCEPTION 'trust configuration event history was deleted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$history_is_append_only_and_tenant_isolated$;

ROLLBACK;

SELECT 'PASS only tenant administrators can create, activate, rollback and inspect trust configurations' AS result;
SELECT 'PASS ranges and weight sums are validated before an immutable draft is stored' AS result;
SELECT 'PASS activation is atomic and rollback appends a new version without rewriting history' AS result;
SELECT 'PASS trust configuration lifecycle events are append-only and tenant isolated' AS result;
