CREATE DOMAIN identity.step_up_factor_id AS text
  CHECK (VALUE ~ '^suf_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN audit.step_up_challenge_id AS text
  CHECK (VALUE ~ '^suc_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TYPE identity.step_up_factor_state AS ENUM ('active', 'revoked');
CREATE TYPE audit.step_up_challenge_state AS ENUM ('issued', 'verified');

CREATE TABLE identity.step_up_factors (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  factor_id identity.step_up_factor_id NOT NULL,
  algorithm text NOT NULL DEFAULT 'Ed25519',
  public_key_base64url trust.ed25519_public_key_base64url NOT NULL,
  public_key_sha256 text NOT NULL,
  state identity.step_up_factor_state NOT NULL DEFAULT 'active',
  enrolled_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT step_up_factors_pk PRIMARY KEY (tenant_id, subject_id, factor_id),
  CONSTRAINT step_up_factors_membership_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT step_up_factors_algorithm CHECK (algorithm = 'Ed25519'),
  CONSTRAINT step_up_factors_fingerprint_matches CHECK (
    public_key_sha256 = trust.ed25519_public_key_sha256(public_key_base64url)
  ),
  CONSTRAINT step_up_factors_state_shape CHECK (
    (state = 'active' AND revoked_at IS NULL)
    OR (state = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= enrolled_at)
  )
);

CREATE UNIQUE INDEX step_up_factors_active_key_unique
  ON identity.step_up_factors (tenant_id, subject_id, public_key_sha256)
  WHERE state = 'active';

CREATE TABLE audit.step_up_challenges (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  challenge_id audit.step_up_challenge_id NOT NULL,
  factor_id identity.step_up_factor_id NOT NULL,
  action text NOT NULL,
  nonce_base64url text NOT NULL,
  session_id_hash_sha256 text NOT NULL,
  state audit.step_up_challenge_state NOT NULL DEFAULT 'issued',
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT step_up_challenges_pk PRIMARY KEY (tenant_id, challenge_id),
  CONSTRAINT step_up_challenges_factor_fk FOREIGN KEY (tenant_id, subject_id, factor_id)
    REFERENCES identity.step_up_factors (tenant_id, subject_id, factor_id) ON DELETE RESTRICT,
  CONSTRAINT step_up_challenges_action CHECK (action IN ('record:export', 'tenant:admin')),
  CONSTRAINT step_up_challenges_nonce CHECK (nonce_base64url ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT step_up_challenges_session_hash CHECK (session_id_hash_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT step_up_challenges_lifetime CHECK (
    expires_at > issued_at AND expires_at <= issued_at + interval '120 seconds'
  ),
  CONSTRAINT step_up_challenges_state_shape CHECK (
    (state = 'issued' AND verified_at IS NULL)
    OR (state = 'verified' AND verified_at IS NOT NULL AND verified_at >= issued_at AND verified_at <= expires_at)
  )
);

CREATE TABLE audit.step_up_proofs (
  tenant_id identity.tenant_id NOT NULL,
  subject_id identity.subject_id NOT NULL,
  proof_id_hash_sha256 text NOT NULL,
  challenge_id audit.step_up_challenge_id NOT NULL,
  action text NOT NULL,
  session_id_hash_sha256 text NOT NULL,
  verified_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by_request_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT step_up_proofs_pk PRIMARY KEY (tenant_id, proof_id_hash_sha256),
  CONSTRAINT step_up_proofs_challenge_unique UNIQUE (tenant_id, challenge_id),
  CONSTRAINT step_up_proofs_challenge_fk FOREIGN KEY (tenant_id, challenge_id)
    REFERENCES audit.step_up_challenges (tenant_id, challenge_id) ON DELETE RESTRICT,
  CONSTRAINT step_up_proofs_subject_fk FOREIGN KEY (tenant_id, subject_id)
    REFERENCES identity.tenant_memberships (tenant_id, subject_id) ON DELETE RESTRICT,
  CONSTRAINT step_up_proofs_hashes CHECK (
    proof_id_hash_sha256 ~ '^[0-9a-f]{64}$' AND session_id_hash_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT step_up_proofs_action CHECK (action IN ('record:export', 'tenant:admin')),
  CONSTRAINT step_up_proofs_lifetime CHECK (
    expires_at > verified_at AND expires_at <= verified_at + interval '300 seconds'
  ),
  CONSTRAINT step_up_proofs_consumption_shape CHECK (
    (consumed_at IS NULL AND consumed_by_request_id IS NULL)
    OR (
      consumed_at IS NOT NULL
      AND consumed_at >= verified_at
      AND consumed_by_request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
  )
);

CREATE INDEX step_up_proofs_unconsumed_lookup
  ON audit.step_up_proofs (tenant_id, subject_id, action, proof_id_hash_sha256)
  WHERE consumed_at IS NULL;

ALTER TABLE identity.step_up_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.step_up_factors FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.step_up_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.step_up_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.step_up_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.step_up_proofs FORCE ROW LEVEL SECURITY;

CREATE FUNCTION identity.enroll_step_up_factor(
  p_factor_id identity.step_up_factor_id,
  p_public_key trust.ed25519_public_key_base64url,
  p_enrolled_at timestamptz
)
RETURNS identity.step_up_factors
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
  v_factor identity.step_up_factors%ROWTYPE;
BEGIN
  IF v_tenant_id IS NULL OR v_subject_id IS NULL OR NOT identity.current_actor_is_active()
     OR p_enrolled_at IS NULL OR p_enrolled_at > clock_timestamp() + interval '2 seconds'
     OR p_enrolled_at < clock_timestamp() - interval '5 minutes' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Step-up factor enrollment denied.';
  END IF;
  INSERT INTO identity.step_up_factors (
    tenant_id, subject_id, factor_id, public_key_base64url,
    public_key_sha256, enrolled_at
  ) VALUES (
    v_tenant_id, v_subject_id, p_factor_id, p_public_key,
    trust.ed25519_public_key_sha256(p_public_key), p_enrolled_at
  ) RETURNING * INTO v_factor;
  RETURN v_factor;
END
$function$;

CREATE FUNCTION audit.issue_step_up_challenge(
  p_challenge_id audit.step_up_challenge_id,
  p_factor_id identity.step_up_factor_id,
  p_action text,
  p_nonce_base64url text,
  p_session_id_hash_sha256 text,
  p_issued_at timestamptz,
  p_expires_at timestamptz
)
RETURNS audit.step_up_challenges
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, audit
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
  v_challenge audit.step_up_challenges%ROWTYPE;
BEGIN
  IF v_tenant_id IS NULL OR v_subject_id IS NULL OR NOT identity.current_actor_is_active()
     OR p_action NOT IN ('record:export', 'tenant:admin')
     OR p_issued_at IS NULL OR p_expires_at IS NULL
     OR p_issued_at > clock_timestamp() + interval '2 seconds'
     OR p_issued_at < clock_timestamp() - interval '5 minutes'
     OR p_expires_at <= p_issued_at OR p_expires_at > p_issued_at + interval '120 seconds'
     OR NOT EXISTS (
       SELECT 1 FROM identity.step_up_factors AS factor
       WHERE factor.tenant_id = v_tenant_id AND factor.subject_id = v_subject_id
         AND factor.factor_id = p_factor_id AND factor.state = 'active'
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Step-up challenge issuance denied.';
  END IF;
  INSERT INTO audit.step_up_challenges (
    tenant_id, subject_id, challenge_id, factor_id, action,
    nonce_base64url, session_id_hash_sha256, issued_at, expires_at
  ) VALUES (
    v_tenant_id, v_subject_id, p_challenge_id, p_factor_id, p_action,
    p_nonce_base64url, p_session_id_hash_sha256, p_issued_at, p_expires_at
  ) RETURNING * INTO v_challenge;
  RETURN v_challenge;
END
$function$;

CREATE FUNCTION audit.get_step_up_challenge(p_challenge_id audit.step_up_challenge_id)
RETURNS TABLE (
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  challenge_id audit.step_up_challenge_id,
  factor_id identity.step_up_factor_id,
  action text,
  nonce_base64url text,
  session_id_hash_sha256 text,
  issued_at timestamptz,
  expires_at timestamptz,
  public_key_base64url trust.ed25519_public_key_base64url
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, trust, audit
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
BEGIN
  IF v_tenant_id IS NULL OR v_subject_id IS NULL OR NOT identity.current_actor_is_active() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Step-up challenge lookup denied.';
  END IF;
  RETURN QUERY
  SELECT challenge.tenant_id, challenge.subject_id, challenge.challenge_id,
    challenge.factor_id, challenge.action, challenge.nonce_base64url,
    challenge.session_id_hash_sha256, challenge.issued_at, challenge.expires_at,
    factor.public_key_base64url
  FROM audit.step_up_challenges AS challenge
  JOIN identity.step_up_factors AS factor
    ON factor.tenant_id = challenge.tenant_id
   AND factor.subject_id = challenge.subject_id
   AND factor.factor_id = challenge.factor_id
  WHERE challenge.tenant_id = v_tenant_id AND challenge.subject_id = v_subject_id
    AND challenge.challenge_id = p_challenge_id AND challenge.state = 'issued'
    AND challenge.expires_at >= clock_timestamp() AND factor.state = 'active';
END
$function$;

CREATE FUNCTION audit.complete_step_up_challenge(
  p_challenge_id audit.step_up_challenge_id,
  p_proof_id_hash_sha256 text,
  p_verified_at timestamptz,
  p_expires_at timestamptz
)
RETURNS audit.step_up_proofs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, audit
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
  v_challenge audit.step_up_challenges%ROWTYPE;
  v_proof audit.step_up_proofs%ROWTYPE;
BEGIN
  SELECT * INTO v_challenge FROM audit.step_up_challenges AS challenge
  WHERE challenge.tenant_id = v_tenant_id AND challenge.subject_id = v_subject_id
    AND challenge.challenge_id = p_challenge_id FOR UPDATE;
  IF v_challenge.challenge_id IS NULL OR v_challenge.state <> 'issued'
     OR p_verified_at < v_challenge.issued_at OR p_verified_at > v_challenge.expires_at
     OR p_verified_at > clock_timestamp() + interval '2 seconds'
     OR p_expires_at <= p_verified_at OR p_expires_at > p_verified_at + interval '300 seconds' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Step-up challenge completion denied.';
  END IF;
  UPDATE audit.step_up_challenges SET state = 'verified', verified_at = p_verified_at
  WHERE tenant_id = v_tenant_id AND challenge_id = p_challenge_id;
  INSERT INTO audit.step_up_proofs (
    tenant_id, subject_id, proof_id_hash_sha256, challenge_id,
    action, session_id_hash_sha256, verified_at, expires_at
  ) VALUES (
    v_tenant_id, v_subject_id, p_proof_id_hash_sha256, p_challenge_id,
    v_challenge.action, v_challenge.session_id_hash_sha256, p_verified_at, p_expires_at
  ) RETURNING * INTO v_proof;
  RETURN v_proof;
END
$function$;

CREATE FUNCTION audit.consume_step_up_proof(
  p_proof_id_hash_sha256 text,
  p_session_id_hash_sha256 text,
  p_action text,
  p_request_id text,
  p_consumed_at timestamptz
)
RETURNS TABLE (
  proof_id_hash_sha256 text,
  tenant_id identity.tenant_id,
  subject_id identity.subject_id,
  action text,
  session_id_hash_sha256 text,
  verified_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, audit
SET row_security = off
AS $function$
DECLARE
  v_tenant_id identity.tenant_id := identity.current_tenant_id();
  v_subject_id identity.subject_id := identity.current_subject_id();
BEGIN
  IF v_tenant_id IS NULL OR v_subject_id IS NULL OR NOT identity.current_actor_is_active()
     OR p_consumed_at IS NULL OR p_consumed_at > clock_timestamp() + interval '2 seconds'
     OR p_request_id !~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Step-up proof consumption denied.';
  END IF;
  RETURN QUERY
  UPDATE audit.step_up_proofs AS proof
  SET consumed_at = p_consumed_at, consumed_by_request_id = p_request_id
  WHERE proof.tenant_id = v_tenant_id AND proof.subject_id = v_subject_id
    AND proof.proof_id_hash_sha256 = p_proof_id_hash_sha256
    AND proof.session_id_hash_sha256 = p_session_id_hash_sha256
    AND proof.action = p_action AND proof.consumed_at IS NULL
    AND proof.verified_at <= p_consumed_at AND proof.expires_at >= p_consumed_at
  RETURNING proof.proof_id_hash_sha256, proof.tenant_id, proof.subject_id,
    proof.action, proof.session_id_hash_sha256, proof.verified_at, proof.expires_at;
END
$function$;

REVOKE ALL ON TABLE identity.step_up_factors, audit.step_up_challenges, audit.step_up_proofs
  FROM PUBLIC, tenant_trust_app;
REVOKE ALL ON FUNCTION identity.enroll_step_up_factor(
  identity.step_up_factor_id, trust.ed25519_public_key_base64url, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.issue_step_up_challenge(
  audit.step_up_challenge_id, identity.step_up_factor_id, text, text, text, timestamptz, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.get_step_up_challenge(audit.step_up_challenge_id) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.complete_step_up_challenge(
  audit.step_up_challenge_id, text, timestamptz, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.consume_step_up_proof(text, text, text, text, timestamptz) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity.enroll_step_up_factor(
  identity.step_up_factor_id, trust.ed25519_public_key_base64url, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION audit.issue_step_up_challenge(
  audit.step_up_challenge_id, identity.step_up_factor_id, text, text, text, timestamptz, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION audit.get_step_up_challenge(audit.step_up_challenge_id) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION audit.complete_step_up_challenge(
  audit.step_up_challenge_id, text, timestamptz, timestamptz
) TO tenant_trust_app;
GRANT EXECUTE ON FUNCTION audit.consume_step_up_proof(text, text, text, text, timestamptz)
  TO tenant_trust_app;

COMMENT ON TABLE identity.step_up_factors IS
  'Tenant- and subject-bound Ed25519 possession factors used only for step-up authentication';
COMMENT ON TABLE audit.step_up_proofs IS
  'Short-lived action/session-bound step-up proofs stored only by hash and consumed once atomically';
