package tenant_trust.authorization_test

import rego.v1
import data.tenant_trust.authorization

tenant_id := "tnt_018f1234-5678-7abc-8def-0123456789ab"
subject_id := "sub_018f1234-5678-7abc-8def-0123456789ab"

base_input := {
    "schemaVersion": "1.0.0",
    "contractId": "opa-decision-input-v1",
    "identity": {
        "source": "mtls-certificate",
        "authenticationId": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "tenantId": tenant_id,
        "subjectId": subject_id,
        "certificateId": "crt_018f1234-5678-7abc-8def-0123456789ab",
        "issuerId": "iss_018f1234-5678-7abc-8def-0123456789b4",
        "serialNumber": "00000000000000000000000000000001",
        "fingerprintSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "valid": true,
        "certificateState": "active",
        "statusSource": "authoritative",
        "statusVersion": 4,
        "statusObservedAt": "2026-10-20T09:00:00.000Z",
        "checkedAt": "2026-10-20T09:00:00.000Z",
        "validUntil": "2026-10-20T09:05:00.000Z",
    },
    "tenantContext": {
        "tenantId": tenant_id,
        "subjectId": subject_id,
        "roles": ["tenant-member"],
        "tenantState": "active",
        "subjectState": "active",
        "membershipState": "active",
        "versions": {"tenant": 2, "subject": 3, "membership": 4},
    },
    "action": "profile:read",
    "resource": {
        "tenantId": tenant_id,
        "resourceType": "subject-profile",
        "resourceIdHashSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "sensitivity": "confidential",
        "scope": "self",
        "ownerSubjectId": subject_id,
    },
    "trust": {
        "tenantId": tenant_id,
        "subjectId": subject_id,
        "state": "fresh",
        "usableForPolicy": true,
        "requiredOutcome": null,
        "reasonCode": null,
        "policyScore": 80,
        "policyBand": "high",
        "lastKnownScore": 80,
        "lastKnownBand": "high",
        "ageSeconds": 2,
        "staleAfterSeconds": 300,
        "transitionId": "trn_018f1234-5678-7abc-8def-0123456789ab",
        "updateVersion": 5,
        "modelVersion": "1.0.0",
        "configurationVersion": 1,
        "observedAt": "2026-10-20T08:59:58.000Z",
        "evaluatedAt": "2026-10-20T09:00:00.000Z",
        "recordedAt": "2026-10-20T09:00:00.000Z",
        "explanationHashSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    },
    "requestContext": {
        "requestId": "req_018f1234-5678-7abc-8def-0123456789ab",
        "correlationId": "cor_018f1234-5678-7abc-8def-0123456789ab",
        "requestedAt": "2026-10-20T09:00:00.000Z",
        "method": "GET",
        "routeTemplate": "/v1/profile",
        "sourceNetworkZone": "external",
        "stepUp": {
            "status": "absent",
            "proofIdHashSha256": null,
            "tenantId": null,
            "subjectId": null,
            "action": null,
            "sessionIdHashSha256": null,
            "verifiedAt": null,
            "expiresAt": null,
        },
    },
}

policy_input(action, sensitivity, score, roles) := object.union(base_input, {
    "action": action,
    "tenantContext": object.union(base_input.tenantContext, {"roles": roles}),
    "resource": object.union(base_input.resource, {"sensitivity": sensitivity}),
    "trust": object.union(base_input.trust, {
        "policyScore": score,
        "lastKnownScore": score,
    }),
})

test_score_below_quarantine_cutoff_returns_quarantine if {
    candidate := policy_input("profile:read", "confidential", 49.99, ["tenant-member"])
    result := authorization.decision with input as candidate
    result.outcome == "QUARANTINE"
    result.reasonCodes == ["TRUST_SCORE_QUARANTINE"]
    result.obligations.quarantine.actionType == "restrict-access"
}

test_quarantine_boundary_is_exclusive if {
    candidate := policy_input("profile:read", "confidential", 50, ["tenant-member"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
    result.reasonCodes == ["TRUST_SCORE_BELOW_ACTION_MINIMUM"]
}

test_profile_read_is_denied_immediately_below_55 if {
    candidate := policy_input("profile:read", "confidential", 54.99, ["tenant-member"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
}

test_profile_read_is_allowed_at_exactly_55 if {
    candidate := policy_input("profile:read", "confidential", 55, ["tenant-member"])
    result := authorization.decision with input as candidate
    result.outcome == "ALLOW"
    result.reasonCodes == ["POLICY_ALLOW"]
}

test_sensitive_export_is_denied_immediately_below_65 if {
    candidate := policy_input("record:export", "sensitive", 64.99, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
}

test_sensitive_export_requires_step_up_at_exactly_65 if {
    candidate := policy_input("record:export", "sensitive", 65, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "STEP_UP"
    result.obligations.stepUp.binding == ["tenant", "subject", "action", "session"]
}

test_sensitive_export_allows_a_fresh_bound_step_up_proof if {
    candidate := policy_input("record:export", "sensitive", 65, ["tenant-admin"])
    bound := object.union(candidate, {
        "requestContext": object.union(candidate.requestContext, {
            "stepUp": {
                "status": "valid",
                "proofIdHashSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "tenantId": tenant_id,
                "subjectId": subject_id,
                "action": "record:export",
                "sessionIdHashSha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "verifiedAt": "2026-10-20T08:59:30.000Z",
                "expiresAt": "2026-10-20T09:04:30.000Z",
            },
        }),
    })
    result := authorization.decision with input as bound
    result.outcome == "ALLOW"
}

test_step_up_proof_for_another_action_is_not_accepted if {
    candidate := policy_input("record:export", "sensitive", 65, ["tenant-admin"])
    mismatched := object.union(candidate, {
        "requestContext": object.union(candidate.requestContext, {
            "stepUp": {
                "status": "valid",
                "proofIdHashSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "tenantId": tenant_id,
                "subjectId": subject_id,
                "action": "tenant:admin",
                "sessionIdHashSha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "verifiedAt": "2026-10-20T08:59:30.000Z",
                "expiresAt": "2026-10-20T09:04:30.000Z",
            },
        }),
    })
    result := authorization.decision with input as mismatched
    result.outcome == "STEP_UP"
}

test_expired_step_up_proof_is_not_accepted if {
    candidate := policy_input("record:export", "sensitive", 65, ["tenant-admin"])
    expired := object.union(candidate, {
        "requestContext": object.union(candidate.requestContext, {
            "stepUp": {
                "status": "valid",
                "proofIdHashSha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "tenantId": tenant_id,
                "subjectId": subject_id,
                "action": "record:export",
                "sessionIdHashSha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "verifiedAt": "2026-10-20T08:54:00.000Z",
                "expiresAt": "2026-10-20T08:59:00.000Z",
            },
        }),
    })
    result := authorization.decision with input as expired
    result.outcome == "STEP_UP"
}

test_critical_tenant_admin_is_denied_immediately_below_80 if {
    candidate := policy_input("tenant:admin", "critical", 79.99, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
}

test_critical_tenant_admin_requires_step_up_at_exactly_80 if {
    candidate := policy_input("tenant:admin", "critical", 80, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "STEP_UP"
}

test_admin_key_rotation_is_denied_immediately_below_90 if {
    candidate := policy_input("admin-key:rotate", "critical", 89.99, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
}

test_admin_key_rotation_requires_step_up_at_exactly_90 if {
    candidate := policy_input("admin-key:rotate", "critical", 90, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "STEP_UP"
    result.obligations.stepUp.maximumAgeSeconds == 300
}

test_sensitivity_downgrade_is_denied if {
    candidate := policy_input("admin-key:rotate", "confidential", 100, ["tenant-admin"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
    result.reasonCodes == ["RESOURCE_SENSITIVITY_MISMATCH"]
}

test_member_cannot_use_an_admin_action if {
    candidate := policy_input("admin-key:rotate", "critical", 100, ["tenant-member"])
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
    result.reasonCodes == ["ROLE_NOT_ELIGIBLE"]
}

test_stale_trust_preserves_the_mandatory_denial if {
    fresh := policy_input("profile:read", "confidential", 100, ["tenant-member"])
    candidate := object.union(fresh, {
        "trust": object.union(fresh.trust, {
            "state": "stale",
            "usableForPolicy": false,
            "requiredOutcome": "DENY",
            "reasonCode": "TRUST_STATE_STALE",
            "policyScore": null,
            "policyBand": null,
            "ageSeconds": 301,
        }),
    })
    result := authorization.decision with input as candidate
    result.outcome == "DENY"
    result.reasonCodes == ["TRUST_STATE_STALE"]
}
