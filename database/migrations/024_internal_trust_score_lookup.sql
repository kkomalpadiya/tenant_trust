CREATE FUNCTION trust.get_current_actor_trust_score()
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  freshness_state text,
  usable_for_policy boolean,
  required_outcome text,
  reason_code text,
  policy_score numeric,
  policy_band text,
  last_known_score numeric,
  last_known_band text,
  age_seconds numeric,
  stale_after_seconds integer,
  transition_id trust.transition_id,
  update_version bigint,
  model_version text,
  configuration_version integer,
  observed_at timestamptz,
  evaluated_at timestamptz,
  recorded_at timestamptz,
  explanation_hash_sha256 identity.sha256_digest
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
  v_now timestamptz := statement_timestamp();
  v_transition record;
  v_age_seconds numeric;
BEGIN
  IF v_tenant_id IS NULL
     OR v_subject_id IS NULL
     OR NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Current trust lookup denied.';
  END IF;

  SELECT transition.*, configuration.stale_after_seconds
  INTO v_transition
  FROM trust.subject_trust_transition_current AS current_transition
  JOIN trust.subject_trust_transitions AS transition
    ON transition.tenant_id = current_transition.tenant_id
   AND transition.subject_id = current_transition.subject_id
   AND transition.transition_id = current_transition.transition_id
   AND transition.update_version = current_transition.update_version
  JOIN trust.trust_configurations AS configuration
    ON configuration.tenant_id = transition.tenant_id
   AND configuration.configuration_version = transition.configuration_version
   AND configuration.model_version = transition.model_version
  WHERE current_transition.tenant_id = v_tenant_id
    AND current_transition.subject_id = v_subject_id;

  IF NOT FOUND THEN
    RETURN QUERY SELECT
      v_tenant_id, v_subject_id, 'missing'::text, false, 'DENY'::text,
      'TRUST_STATE_MISSING'::text, NULL::numeric, NULL::text, NULL::numeric,
      NULL::text, NULL::numeric, NULL::integer, NULL::trust.transition_id,
      NULL::bigint, NULL::text, NULL::integer, NULL::timestamptz,
      NULL::timestamptz, NULL::timestamptz, NULL::identity.sha256_digest;
    RETURN;
  END IF;

  v_age_seconds := round(
    greatest(0::numeric, extract(epoch FROM (v_now - v_transition.evaluated_at))),
    3
  );
  IF v_age_seconds <= v_transition.stale_after_seconds THEN
    RETURN QUERY SELECT
      v_tenant_id, v_subject_id, 'fresh'::text, true, NULL::text, NULL::text,
      v_transition.new_score, v_transition.new_band, v_transition.new_score,
      v_transition.new_band, v_age_seconds, v_transition.stale_after_seconds,
      v_transition.transition_id, v_transition.update_version,
      v_transition.model_version, v_transition.configuration_version,
      v_transition.observed_at, v_transition.evaluated_at, v_transition.recorded_at,
      v_transition.explanation_hash_sha256;
  ELSE
    RETURN QUERY SELECT
      v_tenant_id, v_subject_id, 'stale'::text, false, 'DENY'::text,
      'TRUST_STATE_STALE'::text, NULL::numeric, NULL::text,
      v_transition.new_score, v_transition.new_band, v_age_seconds,
      v_transition.stale_after_seconds, v_transition.transition_id,
      v_transition.update_version, v_transition.model_version,
      v_transition.configuration_version, v_transition.observed_at,
      v_transition.evaluated_at, v_transition.recorded_at,
      v_transition.explanation_hash_sha256;
  END IF;
END
$function$;

REVOKE ALL ON FUNCTION trust.get_current_actor_trust_score() FROM PUBLIC;
GRANT USAGE ON SCHEMA trust TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION trust.get_current_actor_trust_score() TO tenant_trust_app;

COMMENT ON FUNCTION trust.get_current_actor_trust_score() IS
  'Returns only the transaction-bound actor current trust score when fresh; stale and missing state require DENY';
