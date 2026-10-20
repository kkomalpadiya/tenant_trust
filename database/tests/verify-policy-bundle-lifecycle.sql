\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab'
);

DO $member_denied$
DECLARE
  v_time timestamptz := clock_timestamp();
  v_document text;
BEGIN
  v_document := jsonb_build_object(
    'schemaVersion', '1.0.0',
    'tenantId', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'policyVersionId', 'pol_018f1234-5678-7abc-8def-0123456789c2',
    'policyName', 'access-control',
    'bundleVersion', 2,
    'entrypoint', 'tenant_trust/authorization/decision',
    'modules', jsonb_build_array(jsonb_build_object(
      'path', 'tenant_trust/authorization.rego',
      'source', E'package tenant_trust.authorization\n\ndefault decision := null\n'
    )),
    'data', '{}'::jsonb,
    'validation', jsonb_build_object(
      'engine', 'opa', 'engineVersion', '1.20.2', 'regoVersion', 'v1', 'checkedAt', v_time
    )
  )::text;
  BEGIN
    PERFORM trust.publish_policy_bundle(
      'pol_018f1234-5678-7abc-8def-0123456789c2', 'access-control', 2,
      encode(public.digest(convert_to(v_document, 'UTF8'), 'sha256'), 'hex'),
      'tenant_trust/authorization/decision', v_document, '1.20.2', 'v1',
      'MEMBER_PROBE', v_time
    );
    RAISE EXCEPTION 'ordinary member published a policy bundle';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM trust.list_policy_bundle_history('access-control');
    RAISE EXCEPTION 'ordinary member read policy bundle administration history';
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

DO $publish_validate_activate$
DECLARE
  v_time timestamptz := clock_timestamp();
  v_document text;
  v_hash text;
BEGIN
  v_document := jsonb_build_object(
    'schemaVersion', '1.0.0',
    'tenantId', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'policyVersionId', 'pol_018f1234-5678-7abc-8def-0123456789c2',
    'policyName', 'access-control',
    'bundleVersion', 2,
    'entrypoint', 'tenant_trust/authorization/decision',
    'modules', jsonb_build_array(jsonb_build_object(
      'path', 'tenant_trust/authorization.rego',
      'source', E'package tenant_trust.authorization\n\ndefault decision := null\n'
    )),
    'data', jsonb_build_object('thresholds', '{}'::jsonb),
    'validation', jsonb_build_object(
      'engine', 'opa', 'engineVersion', '1.20.2', 'regoVersion', 'v1', 'checkedAt', v_time
    )
  )::text;
  v_hash := encode(public.digest(convert_to(v_document, 'UTF8'), 'sha256'), 'hex');

  BEGIN
    PERFORM trust.publish_policy_bundle(
      'pol_018f1234-5678-7abc-8def-0123456789c2', 'access-control', 2,
      repeat('a', 64), 'tenant_trust/authorization/decision', v_document,
      '1.20.2', 'v1', 'INVALID_HASH', v_time
    );
    RAISE EXCEPTION 'bundle with a mismatched digest was published';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;

  PERFORM trust.publish_policy_bundle(
    'pol_018f1234-5678-7abc-8def-0123456789c2', 'access-control', 2,
    v_hash, 'tenant_trust/authorization/decision', v_document,
    '1.20.2', 'v1', 'PUBLISH_VALIDATED_BUNDLE', v_time
  );

  IF NOT EXISTS (
    SELECT 1 FROM trust.list_policy_bundle_history('access-control')
    WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c2'
      AND bundle_version = 2
      AND state = 'published'
      AND bundle_hash_sha256 = v_hash
      AND validation_engine = 'opa'
      AND validation_engine_version = '1.20.2'
      AND rego_version = 'v1'
      AND latest_event_type = 'published'
  ) THEN
    RAISE EXCEPTION 'validated policy bundle publication was not recorded';
  END IF;

  BEGIN
    PERFORM trust.activate_policy_bundle(
      'pol_018f1234-5678-7abc-8def-0123456789c0',
      'LEGACY_ACTIVATION_PROBE', clock_timestamp()
    );
    RAISE EXCEPTION 'unvalidated legacy bundle was activated';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  PERFORM trust.activate_policy_bundle(
    'pol_018f1234-5678-7abc-8def-0123456789c2',
    'ACTIVATE_VALIDATED_BUNDLE', clock_timestamp()
  );

  IF (SELECT count(*) FROM trust.policy_versions
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND policy_name = 'access-control' AND state = 'active') <> 1
     OR NOT EXISTS (
       SELECT 1 FROM trust.get_active_policy_bundle('access-control')
       WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c2'
         AND bundle_version = 2
         AND bundle_hash_sha256 = v_hash
         AND entrypoint = 'tenant_trust/authorization/decision'
     ) THEN
    RAISE EXCEPTION 'policy bundle activation did not select one exact active version';
  END IF;

  BEGIN
    INSERT INTO trust.policy_versions (
      tenant_id, policy_version_id, policy_name, bundle_version,
      bundle_hash_sha256, entrypoint, state, published_by_subject_id
    ) VALUES (
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'pol_018f1234-5678-7abc-8def-0123456789cf',
      'access-control', 99, repeat('f', 64),
      'tenant_trust/authorization/decision', 'published',
      'sub_018f1234-5678-7abc-8def-0123456789ac'
    );
    RAISE EXCEPTION 'tenant runtime inserted policy metadata directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$publish_validate_activate$;

DO $atomic_replacement$
DECLARE
  v_time timestamptz := clock_timestamp();
  v_document text;
  v_hash text;
BEGIN
  v_document := jsonb_build_object(
    'schemaVersion', '1.0.0',
    'tenantId', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'policyVersionId', 'pol_018f1234-5678-7abc-8def-0123456789c3',
    'policyName', 'access-control',
    'bundleVersion', 3,
    'entrypoint', 'tenant_trust/authorization/decision',
    'modules', jsonb_build_array(jsonb_build_object(
      'path', 'tenant_trust/authorization.rego',
      'source', E'package tenant_trust.authorization\n\ndefault decision := null\n'
    )),
    'data', jsonb_build_object('thresholds', jsonb_build_object('revision', 2)),
    'validation', jsonb_build_object(
      'engine', 'opa', 'engineVersion', '1.20.2', 'regoVersion', 'v1', 'checkedAt', v_time
    )
  )::text;
  v_hash := encode(public.digest(convert_to(v_document, 'UTF8'), 'sha256'), 'hex');

  PERFORM trust.publish_policy_bundle(
    'pol_018f1234-5678-7abc-8def-0123456789c3', 'access-control', 3,
    v_hash, 'tenant_trust/authorization/decision', v_document,
    '1.20.2', 'v1', 'PUBLISH_REPLACEMENT', v_time
  );
  PERFORM trust.activate_policy_bundle(
    'pol_018f1234-5678-7abc-8def-0123456789c3',
    'ACTIVATE_REPLACEMENT', clock_timestamp()
  );

  IF (SELECT count(*) FROM trust.policy_versions
      WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
        AND policy_name = 'access-control' AND state = 'active') <> 1
     OR NOT EXISTS (
       SELECT 1 FROM trust.policy_versions
       WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
         AND policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c2'
         AND state = 'superseded'
     )
     OR NOT EXISTS (
       SELECT 1 FROM trust.get_active_policy_bundle('access-control')
       WHERE policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c3'
         AND bundle_version = 3 AND bundle_hash_sha256 = v_hash
     ) THEN
    RAISE EXCEPTION 'replacement activation did not atomically supersede the prior bundle';
  END IF;
END
$atomic_replacement$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ac',
  'sub_018f1234-5678-7abc-8def-0123456789ae'
);

DO $beta_cannot_see_or_activate_alpha$
BEGIN
  IF (SELECT count(*) FROM trust.get_active_policy_bundle('access-control')) <> 0 THEN
    RAISE EXCEPTION 'Beta lookup observed Alpha active policy bundle';
  END IF;
  BEGIN
    PERFORM trust.activate_policy_bundle(
      'pol_018f1234-5678-7abc-8def-0123456789c3',
      'CROSS_TENANT_PROBE', clock_timestamp()
    );
    RAISE EXCEPTION 'Beta activated a guessed Alpha bundle';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$beta_cannot_see_or_activate_alpha$;
ROLLBACK;

BEGIN;
SET LOCAL ROLE tenant_trust_app;
SELECT identity.set_tenant_actor_context(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ac'
);

DO $history_is_immutable$
DECLARE
  v_time timestamptz := clock_timestamp();
  v_document text;
  v_hash text;
BEGIN
  v_document := jsonb_build_object(
    'schemaVersion', '1.0.0',
    'tenantId', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'policyVersionId', 'pol_018f1234-5678-7abc-8def-0123456789c2',
    'policyName', 'access-control', 'bundleVersion', 2,
    'entrypoint', 'tenant_trust/authorization/decision',
    'modules', jsonb_build_array(jsonb_build_object(
      'path', 'tenant_trust/authorization.rego', 'source', 'package tenant_trust.authorization'
    )),
    'data', '{}'::jsonb,
    'validation', jsonb_build_object(
      'engine', 'opa', 'engineVersion', '1.20.2', 'regoVersion', 'v1', 'checkedAt', v_time
    )
  )::text;
  v_hash := encode(public.digest(convert_to(v_document, 'UTF8'), 'sha256'), 'hex');
  PERFORM trust.publish_policy_bundle(
    'pol_018f1234-5678-7abc-8def-0123456789c2', 'access-control', 2,
    v_hash, 'tenant_trust/authorization/decision', v_document,
    '1.20.2', 'v1', 'HISTORY_TEST', v_time
  );
END
$history_is_immutable$;
RESET ROLE;

DO $owner_cannot_rewrite_history$
BEGIN
  BEGIN
    UPDATE trust.policy_versions
    SET bundle_hash_sha256 = repeat('f', 64)
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c2';
    RAISE EXCEPTION 'published policy bundle content was rewritten';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    DELETE FROM trust.policy_versions
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
      AND policy_version_id = 'pol_018f1234-5678-7abc-8def-0123456789c2';
    RAISE EXCEPTION 'published policy bundle history was deleted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    DELETE FROM trust.policy_bundle_events
    WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab';
    RAISE EXCEPTION 'policy bundle event history was deleted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$owner_cannot_rewrite_history$;
ROLLBACK;

SELECT 'PASS only tenant administrators publish validated immutable policy bundles' AS result;
SELECT 'PASS activation atomically selects one tenant bundle and preserves exact provenance' AS result;
SELECT 'PASS active lookups and administration remain tenant isolated' AS result;
SELECT 'PASS policy bundle and lifecycle event history are append-only' AS result;
