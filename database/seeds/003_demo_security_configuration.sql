\set ON_ERROR_STOP on

BEGIN;

INSERT INTO identity.tenant_issuer_mappings (
  tenant_id, issuer_id, issuer_name, authority_url, state
)
VALUES
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'iss_018f1234-5678-7abc-8def-0123456789b4',
    'tenant-alpha-intermediate',
    'https://issuer.tenant-alpha.invalid',
    'planned'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ac',
    'iss_018f1234-5678-7abc-8def-0123456789b5',
    'tenant-beta-intermediate',
    'https://issuer.tenant-beta.invalid',
    'planned'
  )
ON CONFLICT DO NOTHING;

INSERT INTO trust.evidence_sources (
  tenant_id, source_id, issuer_id, source_name, evidence_type,
  state, verification_algorithm, maximum_age_seconds, synthetic
)
VALUES
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b6', NULL, 'alpha-identity-simulator', 'identity', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b7', NULL, 'alpha-device-simulator', 'device', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b8', NULL, 'alpha-behaviour-simulator', 'behaviour', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789b9', 'iss_018f1234-5678-7abc-8def-0123456789b4', 'alpha-certificate-monitor', 'certificate', 'planned', 'ed25519', 60, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'src_018f1234-5678-7abc-8def-0123456789ba', NULL, 'alpha-compliance-simulator', 'compliance', 'planned', 'ed25519', 3600, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'src_018f1234-5678-7abc-8def-0123456789bb', NULL, 'beta-identity-simulator', 'identity', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'src_018f1234-5678-7abc-8def-0123456789bc', NULL, 'beta-device-simulator', 'device', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'src_018f1234-5678-7abc-8def-0123456789bd', NULL, 'beta-behaviour-simulator', 'behaviour', 'planned', 'ed25519', 300, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'src_018f1234-5678-7abc-8def-0123456789be', 'iss_018f1234-5678-7abc-8def-0123456789b5', 'beta-certificate-monitor', 'certificate', 'planned', 'ed25519', 60, true),
  ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'src_018f1234-5678-7abc-8def-0123456789bf', NULL, 'beta-compliance-simulator', 'compliance', 'planned', 'ed25519', 3600, true)
ON CONFLICT DO NOTHING;

INSERT INTO trust.trust_configurations (
  tenant_id, configuration_version, model_version, state, initial_score,
  smoothing_alpha, maximum_source_influence, stale_after_seconds,
  identity_weight, device_weight, behaviour_weight, certificate_weight,
  compliance_weight, created_by_subject_id, activated_at
)
VALUES
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ab', 1, '1.0.0', 'active', 60,
    0.3000, 0.2500, 3600,
    0.2000, 0.2500, 0.2500, 0.1500, 0.1500,
    'sub_018f1234-5678-7abc-8def-0123456789ac', TIMESTAMPTZ '2026-01-01 00:00:00+00'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ac', 1, '1.0.0', 'active', 55,
    0.2500, 0.2000, 1800,
    0.2500, 0.2000, 0.2000, 0.2000, 0.1500,
    'sub_018f1234-5678-7abc-8def-0123456789ae', TIMESTAMPTZ '2026-01-01 00:00:00+00'
  )
ON CONFLICT DO NOTHING;

INSERT INTO trust.policy_versions (
  tenant_id, policy_version_id, policy_name, bundle_version,
  bundle_hash_sha256, entrypoint, state, published_by_subject_id
)
VALUES
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'pol_018f1234-5678-7abc-8def-0123456789c0',
    'access-control', 1,
    '57598d5bb1d2d3d4696adbf49a2745989f11ef5303e8b585e8dd613ce42fe60e',
    'tenant_trust/authz/decision', 'published',
    'sub_018f1234-5678-7abc-8def-0123456789ac'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ac',
    'pol_018f1234-5678-7abc-8def-0123456789c1',
    'access-control', 1,
    'eb6c15f83b59b8fbc8c088537574a57a2878b9d66f9e830767f860a3f6f5b61f',
    'tenant_trust/authz/decision', 'published',
    'sub_018f1234-5678-7abc-8def-0123456789ae'
  )
ON CONFLICT DO NOTHING;

DO $verify_demo_security_configuration$
BEGIN
  IF (
    SELECT count(*)
    FROM identity.tenant_issuer_mappings
    WHERE (tenant_id, issuer_id, issuer_name, state) IN (
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'iss_018f1234-5678-7abc-8def-0123456789b4', 'tenant-alpha-intermediate', 'planned'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'iss_018f1234-5678-7abc-8def-0123456789b5', 'tenant-beta-intermediate', 'planned')
    )
  ) <> 2 THEN
    RAISE EXCEPTION 'deterministic tenant issuer mappings conflict with existing data';
  END IF;

  IF (
    SELECT count(*)
    FROM trust.evidence_sources
    WHERE source_id IN (
      'src_018f1234-5678-7abc-8def-0123456789b6',
      'src_018f1234-5678-7abc-8def-0123456789b7',
      'src_018f1234-5678-7abc-8def-0123456789b8',
      'src_018f1234-5678-7abc-8def-0123456789b9',
      'src_018f1234-5678-7abc-8def-0123456789ba',
      'src_018f1234-5678-7abc-8def-0123456789bb',
      'src_018f1234-5678-7abc-8def-0123456789bc',
      'src_018f1234-5678-7abc-8def-0123456789bd',
      'src_018f1234-5678-7abc-8def-0123456789be',
      'src_018f1234-5678-7abc-8def-0123456789bf'
    )
      AND state = 'planned'
      AND synthetic
  ) <> 10 THEN
    RAISE EXCEPTION 'deterministic tenant evidence sources conflict with existing data';
  END IF;

  IF (
    SELECT count(*)
    FROM trust.trust_configurations
    WHERE configuration_version = 1
      AND model_version = '1.0.0'
      AND state = 'active'
      AND tenant_id IN (
        'tnt_018f1234-5678-7abc-8def-0123456789ab',
        'tnt_018f1234-5678-7abc-8def-0123456789ac'
      )
  ) <> 2 THEN
    RAISE EXCEPTION 'deterministic tenant trust configurations conflict with existing data';
  END IF;

  IF (
    SELECT count(*)
    FROM trust.policy_versions
    WHERE (tenant_id, policy_version_id, policy_name, bundle_version, state) IN (
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'pol_018f1234-5678-7abc-8def-0123456789c0', 'access-control', 1, 'published'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'pol_018f1234-5678-7abc-8def-0123456789c1', 'access-control', 1, 'published')
    )
  ) <> 2 THEN
    RAISE EXCEPTION 'deterministic tenant policy versions conflict with existing data';
  END IF;
END
$verify_demo_security_configuration$;

COMMIT;

\echo 'Provisioned deterministic tenant-owned issuer, evidence, trust and policy configuration.'
