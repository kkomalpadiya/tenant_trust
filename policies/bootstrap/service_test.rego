package tenant_trust.bootstrap_test

import data.tenant_trust.bootstrap

test_service_is_ready if {
    bootstrap.service.ready == true
    bootstrap.service.policy_api_version == "v1"
}
