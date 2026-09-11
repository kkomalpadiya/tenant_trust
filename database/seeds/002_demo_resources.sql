\set ON_ERROR_STOP on

BEGIN;

INSERT INTO app.resources (tenant_id, resource_id, owner_subject_id, resource_name)
VALUES
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'res_018f1234-5678-7abc-8def-0123456789b0',
    'sub_018f1234-5678-7abc-8def-0123456789ab',
    'Alpha member record'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'res_018f1234-5678-7abc-8def-0123456789b1',
    'sub_018f1234-5678-7abc-8def-0123456789ac',
    'Alpha administrator record'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ac',
    'res_018f1234-5678-7abc-8def-0123456789b2',
    'sub_018f1234-5678-7abc-8def-0123456789ad',
    'Beta member record'
  ),
  (
    'tnt_018f1234-5678-7abc-8def-0123456789ac',
    'res_018f1234-5678-7abc-8def-0123456789b3',
    'sub_018f1234-5678-7abc-8def-0123456789ae',
    'Beta administrator record'
  )
ON CONFLICT DO NOTHING;

DO $verify_demo_resource_conflicts$
BEGIN
  IF (
    SELECT count(*)
    FROM app.resources
    WHERE (tenant_id, resource_id, owner_subject_id, resource_name) IN (
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'res_018f1234-5678-7abc-8def-0123456789b0', 'sub_018f1234-5678-7abc-8def-0123456789ab', 'Alpha member record'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ab', 'res_018f1234-5678-7abc-8def-0123456789b1', 'sub_018f1234-5678-7abc-8def-0123456789ac', 'Alpha administrator record'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'res_018f1234-5678-7abc-8def-0123456789b2', 'sub_018f1234-5678-7abc-8def-0123456789ad', 'Beta member record'),
      ('tnt_018f1234-5678-7abc-8def-0123456789ac', 'res_018f1234-5678-7abc-8def-0123456789b3', 'sub_018f1234-5678-7abc-8def-0123456789ae', 'Beta administrator record')
    )
  ) <> 4 THEN
    RAISE EXCEPTION 'deterministic resource IDs or ownership conflict with existing data';
  END IF;
END
$verify_demo_resource_conflicts$;

COMMIT;

\echo 'Provisioned deterministic Tenant Alpha and Tenant Beta resources.'
