package tenant_trust.authorization

import rego.v1

policy_configuration := data.tenant_trust_policy.authorization.configuration
runtime_policy := data.tenant_trust_policy.authorization.runtime.policy

default decision := null

decision := {
    "schemaVersion": "1.0.0",
    "contractId": "opa-decision-output-v1",
    "decisionId": decision_id,
    "requestId": input.requestContext.requestId,
    "correlationId": input.requestContext.correlationId,
    "tenantId": input.tenantContext.tenantId,
    "subjectId": input.tenantContext.subjectId,
    "outcome": result.outcome,
    "reasonCodes": result.reasonCodes,
    "evaluatedAt": time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05.000Z07:00"]),
    "input": {
        "contractId": input.contractId,
        "hashSha256": crypto.sha256(json.marshal(input)),
    },
    "policy": runtime_policy,
    "state": {
        "certificateStatusVersion": input.identity.statusVersion,
        "tenantVersion": input.tenantContext.versions.tenant,
        "subjectVersion": input.tenantContext.versions.subject,
        "membershipVersion": input.tenantContext.versions.membership,
        "trustTransitionId": input.trust.transitionId,
        "trustUpdateVersion": input.trust.updateVersion,
        "trustConfigurationVersion": input.trust.configurationVersion,
    },
    "obligations": result.obligations,
} if {
    runtime_policy_valid
    result := policy_result
    request_uuid := split(input.requestContext.requestId, "req_")[1]
    decision_id := sprintf("dec_%s", [request_uuid])
}

runtime_policy_valid if {
    regex.match("^pol_[0-9a-f-]{36}$", runtime_policy.policyVersionId)
    runtime_policy.bundleVersion >= 1
    regex.match("^[0-9a-f]{64}$", runtime_policy.bundleHashSha256)
    runtime_policy.decisionPath == "tenant_trust/authorization/decision"
}

configuration_valid if {
    policy_configuration.schemaVersion == "1.0.0"
    policy_configuration.calibrationStatus == "unvalidated-prototype-defaults"
    policy_configuration.tenantId == input.tenantContext.tenantId
    policy_configuration.scoreBands.quarantineBelow > 0
    policy_configuration.scoreBands.quarantineBelow < policy_configuration.scoreBands.restrictedBelow
    policy_configuration.scoreBands.restrictedBelow < policy_configuration.scoreBands.conditionalBelow
    policy_configuration.scoreBands.conditionalBelow < policy_configuration.scoreBands.maximum
    policy_configuration.scoreBands.maximum == 100
    policy_configuration.stepUpMaximumAgeSeconds >= 1
    policy_configuration.stepUpMaximumAgeSeconds <= 900
    policy_configuration.quarantineAction == "restrict-access"
}

binding_valid if {
    input.identity.tenantId == input.tenantContext.tenantId
    input.identity.subjectId == input.tenantContext.subjectId
    input.resource.tenantId == input.tenantContext.tenantId
    input.trust.tenantId == input.tenantContext.tenantId
    input.trust.subjectId == input.tenantContext.subjectId
}

identity_valid if {
    input.identity.valid == true
    input.identity.certificateState == "active"
    input.identity.statusSource == "authoritative"
}

authority_active if {
    input.tenantContext.tenantState == "active"
    input.tenantContext.subjectState == "active"
    input.tenantContext.membershipState == "active"
}

trust_usable if {
    input.trust.state == "fresh"
    input.trust.usableForPolicy == true
    input.trust.requiredOutcome == null
    input.trust.policyScore == input.trust.lastKnownScore
    input.trust.policyBand == input.trust.lastKnownBand
    input.trust.ageSeconds <= input.trust.staleAfterSeconds
}

configured_rule := rule if {
    some rule in policy_configuration.actionRules
    rule.action == input.action
}

role_eligible(rule) if {
    some role in input.tenantContext.roles
    role in rule.roles
}

step_up_proof_valid(rule) if {
    rule.stepUpRequired == true
    input.requestContext.stepUp.status == "valid"
    input.requestContext.stepUp.tenantId == input.tenantContext.tenantId
    input.requestContext.stepUp.subjectId == input.tenantContext.subjectId
    input.requestContext.stepUp.action == input.action
    regex.match("^[0-9a-f]{64}$", input.requestContext.stepUp.proofIdHashSha256)
    regex.match("^[0-9a-f]{64}$", input.requestContext.stepUp.sessionIdHashSha256)
    verified_at := time.parse_rfc3339_ns(input.requestContext.stepUp.verifiedAt)
    expires_at := time.parse_rfc3339_ns(input.requestContext.stepUp.expiresAt)
    requested_at := time.parse_rfc3339_ns(input.requestContext.requestedAt)
    verified_at <= requested_at
    requested_at <= expires_at
    requested_at - verified_at <= policy_configuration.stepUpMaximumAgeSeconds * 1000000000
}

trust_reason := input.trust.reasonCode if {
    input.trust.reasonCode != null
} else := "TRUST_STATE_UNUSABLE"

policy_result := deny_result("POLICY_CONFIGURATION_INVALID") if {
    not configuration_valid
} else := deny_result("TENANT_BINDING_MISMATCH") if {
    not binding_valid
} else := deny_result("CERTIFICATE_INVALID") if {
    not identity_valid
} else := deny_result("TENANT_AUTHORITY_INACTIVE") if {
    not authority_active
} else := deny_result(trust_reason) if {
    not trust_usable
} else := quarantine_result if {
    input.trust.policyScore < policy_configuration.scoreBands.quarantineBelow
} else := deny_result("ACTION_NOT_CONFIGURED") if {
    not configured_rule
} else := deny_result("RESOURCE_SENSITIVITY_MISMATCH") if {
    rule := configured_rule
    rule.sensitivity != input.resource.sensitivity
} else := deny_result("ROLE_NOT_ELIGIBLE") if {
    rule := configured_rule
    not role_eligible(rule)
} else := deny_result("TRUST_SCORE_BELOW_ACTION_MINIMUM") if {
    rule := configured_rule
    input.trust.policyScore < rule.minimumScore
} else := step_up_result if {
    rule := configured_rule
    rule.stepUpRequired == true
    not step_up_proof_valid(rule)
} else := allow_result

deny_result(reason) := {
    "outcome": "DENY",
    "reasonCodes": [reason],
    "obligations": {"stepUp": null, "quarantine": null},
}

quarantine_result := {
    "outcome": "QUARANTINE",
    "reasonCodes": ["TRUST_SCORE_QUARANTINE"],
    "obligations": {
        "stepUp": null,
        "quarantine": {
            "required": true,
            "actionType": policy_configuration.quarantineAction,
        },
    },
}

step_up_result := {
    "outcome": "STEP_UP",
    "reasonCodes": ["STEP_UP_REQUIRED"],
    "obligations": {
        "stepUp": {
            "required": true,
            "binding": ["tenant", "subject", "action", "session"],
            "maximumAgeSeconds": policy_configuration.stepUpMaximumAgeSeconds,
        },
        "quarantine": null,
    },
}

allow_result := {
    "outcome": "ALLOW",
    "reasonCodes": ["POLICY_ALLOW"],
    "obligations": {"stepUp": null, "quarantine": null},
}
