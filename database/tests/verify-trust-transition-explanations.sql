-- This focused verifier is injected into the rolled-back trust-state fixture by
-- scripts/verify-trust-transition-explanations.mjs. The fixture supplies one
-- current state (version 2) and its five durable evidence references.

DO $verify_transition_schema$
DECLARE
  secured_table_count integer;
  append_trigger_count integer;
BEGIN
  SELECT count(*) INTO secured_table_count
  FROM pg_class AS relation
  JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
  WHERE (namespace.nspname, relation.relname) IN (
    ('trust', 'subject_trust_transitions'),
    ('trust', 'subject_trust_transition_contributions'),
    ('trust', 'subject_trust_transition_current'),
    ('trust', 'trust_transition_events')
  )
    AND relation.relrowsecurity
    AND relation.relforcerowsecurity;
  IF secured_table_count <> 4 THEN
    RAISE EXCEPTION 'expected four forced-RLS transition tables, found %', secured_table_count;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'trust'
      AND tablename IN (
        'subject_trust_transitions', 'subject_trust_transition_contributions',
        'subject_trust_transition_current', 'trust_transition_events'
      )
  ) THEN
    RAISE EXCEPTION 'transition tables unexpectedly expose row policies';
  END IF;

  IF has_table_privilege('tenant_trust_trust_engine', 'trust.subject_trust_transitions', 'SELECT')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.subject_trust_transition_contributions', 'INSERT')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.subject_trust_transition_current', 'UPDATE')
     OR has_table_privilege('tenant_trust_trust_engine', 'trust.trust_transition_events', 'SELECT') THEN
    RAISE EXCEPTION 'trust engine received direct transition-table privileges';
  END IF;

  SELECT count(*) INTO append_trigger_count
  FROM pg_trigger
  WHERE (tgrelid, tgname) IN (
    ('trust.subject_trust_transitions'::regclass, 'subject_trust_transitions_keep_history'),
    ('trust.subject_trust_transition_contributions'::regclass, 'subject_trust_transition_contributions_keep_history'),
    ('trust.trust_transition_events'::regclass, 'trust_transition_events_keep_history')
  )
    AND NOT tgisinternal;
  IF append_trigger_count <> 3 THEN
    RAISE EXCEPTION 'transition append-only triggers are incomplete';
  END IF;

  IF NOT has_function_privilege(
    'tenant_trust_trust_engine',
    'trust.record_subject_trust_transition(identity.tenant_id,identity.subject_id,trust.transition_id,identity.event_id,identity.correlation_id,identity.event_id,bigint,trust.transition_id,numeric,text,integer,numeric,text,integer,numeric,numeric,text,timestamptz,timestamptz,text,integer,jsonb,text,identity.sha256_digest,text,identity.sha256_digest)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'trust engine cannot record transitions through the controlled function';
  END IF;
END
$verify_transition_schema$;

CREATE TEMP TABLE trust_transition_test_payload (
  contributions jsonb NOT NULL,
  explanation_json text NOT NULL,
  explanation_hash identity.sha256_digest NOT NULL,
  event_json text NOT NULL,
  event_hash identity.sha256_digest NOT NULL
) ON COMMIT DROP;

INSERT INTO trust_transition_test_payload
WITH contributions AS (
  SELECT jsonb_agg(
    jsonb_build_object(
      'componentId', reference->>'evidenceType',
      'normalizedValue', CASE reference->>'evidenceType'
        WHEN 'identity' THEN 92 WHEN 'device' THEN 83 WHEN 'behaviour' THEN 77
        WHEN 'certificate' THEN 100 WHEN 'compliance' THEN 89 END,
      'weight', CASE reference->>'evidenceType'
        WHEN 'identity' THEN 0.20 WHEN 'device' THEN 0.25 WHEN 'behaviour' THEN 0.25
        WHEN 'certificate' THEN 0.15 WHEN 'compliance' THEN 0.15 END,
      'weightedContribution', CASE reference->>'evidenceType'
        WHEN 'identity' THEN 18.4 WHEN 'device' THEN 20.75 WHEN 'behaviour' THEN 19.25
        WHEN 'certificate' THEN 15 WHEN 'compliance' THEN 13.35 END,
      'evidenceId', reference->>'evidenceId',
      'sourceEventId', reference->>'sourceEventId'
    ) ORDER BY reference->>'evidenceType'
  ) AS value
  FROM trust_state_test_references,
       jsonb_array_elements(evidence_references) AS item(reference)
), explanation AS (
  SELECT jsonb_build_object(
    'transitionId', 'trn_018f1234-5678-7abc-8def-0123456789f0',
    'tenantId', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
    'subjectId', 'sub_018f1234-5678-7abc-8def-0123456789ab',
    'updateVersion', 2,
    'modelVersion', '1.0.0',
    'configurationVersion', 1,
    'previousState', jsonb_build_object('score', 60, 'band', 'uninitialized', 'recoveryStreak', 0),
    'newState', jsonb_build_object('score', 68.03, 'band', 'medium', 'recoveryStreak', 0),
    'evidenceReferences', (
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceType', entry.item->>'componentId',
        'evidenceId', entry.item->>'evidenceId',
        'sourceEventId', entry.item->>'sourceEventId'
      ) ORDER BY entry.item->>'componentId')
      FROM jsonb_array_elements(contributions.value) AS entry(item)
    ),
    'weightedCalculation', jsonb_build_object('score', 86.75, 'contributions', contributions.value),
    'temporalCalculation', jsonb_build_object('score', 68.03, 'alpha', 0.30),
    'transitionControl', jsonb_build_object('transition', 'held')
  )::text AS value,
  contributions.value AS contributions
  FROM contributions
), event AS (
  SELECT explanation.value AS explanation_json,
         explanation.contributions,
         encode(digest(convert_to(explanation.value, 'UTF8'), 'sha256'), 'hex') AS explanation_hash,
         jsonb_build_object(
           'schemaVersion', '1.0.0',
           'eventId', 'evt_018f1234-5678-7abc-8def-0123456789f0',
           'eventType', 'trust.updated.v1',
           'tenantId', 'tnt_018f1234-5678-7abc-8def-0123456789ab',
           'subjectId', 'sub_018f1234-5678-7abc-8def-0123456789ab',
           'aggregateId', 'trn_018f1234-5678-7abc-8def-0123456789f0',
           'correlationId', 'cor_018f1234-5678-7abc-8def-0123456789f0',
           'causationId', 'evt_018f1234-5678-7abc-8def-0123456789e0',
           'payload', jsonb_build_object(
             'transitionId', 'trn_018f1234-5678-7abc-8def-0123456789f0',
             'previousScore', 60,
             'newScore', 68.03,
             'previousBand', 'uninitialized',
             'newBand', 'conditional',
             'modelVersion', '1.0.0',
             'configurationVersion', 1,
             'evidenceIds', (
               SELECT jsonb_agg(entry.item->>'evidenceId' ORDER BY entry.item->>'evidenceId')
               FROM jsonb_array_elements(explanation.contributions) AS entry(item)
             ),
             'explanationHashSha256', encode(digest(convert_to(explanation.value, 'UTF8'), 'sha256'), 'hex')
           )
         )::text AS event_json
  FROM explanation
)
SELECT contributions, explanation_json, explanation_hash, event_json,
       encode(digest(convert_to(event_json, 'UTF8'), 'sha256'), 'hex')
FROM event;

GRANT SELECT ON trust_transition_test_payload TO tenant_trust_trust_engine;
SET LOCAL ROLE tenant_trust_trust_engine;

DO $verify_no_direct_transition_access$
BEGIN
  BEGIN
    PERFORM 1 FROM trust.subject_trust_transitions;
    RAISE EXCEPTION 'trust engine read transition history directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$verify_no_direct_transition_access$;

SELECT * FROM trust.record_subject_trust_transition(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'trn_018f1234-5678-7abc-8def-0123456789f0',
  'evt_018f1234-5678-7abc-8def-0123456789f0',
  'cor_018f1234-5678-7abc-8def-0123456789f0',
  'evt_018f1234-5678-7abc-8def-0123456789e0',
  2, NULL, 60, 'uninitialized', 0, 68.03, 'medium', 0, 86.75, 68.03, 'held',
  TIMESTAMPTZ '2026-10-06 08:05:00+00', clock_timestamp(), '1.0.0', 1,
  (SELECT contributions FROM trust_transition_test_payload),
  (SELECT explanation_json FROM trust_transition_test_payload),
  (SELECT explanation_hash FROM trust_transition_test_payload),
  (SELECT event_json FROM trust_transition_test_payload),
  (SELECT event_hash FROM trust_transition_test_payload)
);

-- An exact retry is idempotent and must not append a second transition or event.
SELECT * FROM trust.record_subject_trust_transition(
  'tnt_018f1234-5678-7abc-8def-0123456789ab',
  'sub_018f1234-5678-7abc-8def-0123456789ab',
  'trn_018f1234-5678-7abc-8def-0123456789f0',
  'evt_018f1234-5678-7abc-8def-0123456789f0',
  'cor_018f1234-5678-7abc-8def-0123456789f0',
  'evt_018f1234-5678-7abc-8def-0123456789e0',
  2, NULL, 60, 'uninitialized', 0, 68.03, 'medium', 0, 86.75, 68.03, 'held',
  TIMESTAMPTZ '2026-10-06 08:05:00+00', clock_timestamp(), '1.0.0', 1,
  (SELECT contributions FROM trust_transition_test_payload),
  (SELECT explanation_json FROM trust_transition_test_payload),
  (SELECT explanation_hash FROM trust_transition_test_payload),
  (SELECT event_json FROM trust_transition_test_payload),
  (SELECT event_hash FROM trust_transition_test_payload)
);

DO $verify_transition_denials$
BEGIN
  BEGIN
    PERFORM trust.record_subject_trust_transition(
      'tnt_018f1234-5678-7abc-8def-0123456789ab',
      'sub_018f1234-5678-7abc-8def-0123456789ab',
      'trn_018f1234-5678-7abc-8def-0123456789f1',
      'evt_018f1234-5678-7abc-8def-0123456789f1',
      'cor_018f1234-5678-7abc-8def-0123456789f0',
      'evt_018f1234-5678-7abc-8def-0123456789e0',
      2, 'trn_018f1234-5678-7abc-8def-0123456789f0', 68.03, 'medium', 0,
      68.03, 'medium', 0, 86.75, 68.03, 'held',
      TIMESTAMPTZ '2026-10-06 08:05:00+00', clock_timestamp(), '1.0.0', 1,
      jsonb_set((SELECT contributions FROM trust_transition_test_payload), '{0,weight}', '0.99'),
      (SELECT explanation_json FROM trust_transition_test_payload),
      (SELECT explanation_hash FROM trust_transition_test_payload),
      (SELECT event_json FROM trust_transition_test_payload),
      (SELECT event_hash FROM trust_transition_test_payload)
    );
    RAISE EXCEPTION 'a forged component contribution was accepted';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;
END
$verify_transition_denials$;

RESET ROLE;

DO $verify_durable_transition$
BEGIN
  IF (SELECT count(*) FROM trust.subject_trust_transitions
      WHERE transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f0') <> 1
     OR (SELECT count(*) FROM trust.subject_trust_transition_contributions
         WHERE transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f0') <> 5
     OR (SELECT count(*) FROM trust.trust_transition_events
         WHERE transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f0') <> 1
     OR (SELECT update_version FROM trust.subject_trust_transition_current
         WHERE tenant_id = 'tnt_018f1234-5678-7abc-8def-0123456789ab'
           AND subject_id = 'sub_018f1234-5678-7abc-8def-0123456789ab') <> 2 THEN
    RAISE EXCEPTION 'transition, contributions, event or current pointer are incomplete';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM trust.subject_trust_transitions AS transition
    JOIN trust.trust_transition_events AS event
      USING (tenant_id, transition_id)
    WHERE transition.transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f0'
      AND transition.explanation_hash_sha256 =
          (SELECT explanation_hash FROM trust_transition_test_payload)
      AND event.event_sha256 =
          (SELECT event_hash FROM trust_transition_test_payload)
  ) THEN
    RAISE EXCEPTION 'transition explanation and event digests are not durably linked';
  END IF;

  BEGIN
    UPDATE trust.subject_trust_transitions
    SET new_score = 0
    WHERE transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f0';
    RAISE EXCEPTION 'transition history was mutable';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    DELETE FROM trust.trust_transition_events
    WHERE transition_id = 'trn_018f1234-5678-7abc-8def-0123456789f0';
    RAISE EXCEPTION 'transition event history was mutable';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$verify_durable_transition$;

\echo 'Verified atomic, append-only trust explanations, contributions and transition events.'
