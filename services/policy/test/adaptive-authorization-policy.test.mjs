import assert from "node:assert/strict";
import test from "node:test";
import {
  ADAPTIVE_AUTHORIZATION_POLICY,
  AdaptiveAuthorizationPolicyError,
  createSlide14PrototypePolicyData,
  validateAdaptiveAuthorizationPolicyData,
} from "../src/index.mjs";

const alpha = "tnt_018f1234-5678-7abc-8def-0123456789ab";
const beta = "tnt_018f1234-5678-7abc-8def-0123456789ac";

function mutableDefault() {
  return structuredClone(createSlide14PrototypePolicyData({ tenantId: alpha }));
}

function rule(data, action) {
  return data.tenant_trust_policy.authorization.configuration.actionRules
    .find((candidate) => candidate.action === action);
}

test("publishes the slide 14 bands as explicitly unvalidated tenant policy defaults", () => {
  const data = createSlide14PrototypePolicyData({ tenantId: alpha });
  const configuration = data.tenant_trust_policy.authorization.configuration;

  assert.equal(configuration.tenantId, alpha);
  assert.equal(configuration.policyProfile, "slide-14-prototype-v1");
  assert.equal(configuration.calibrationStatus, "unvalidated-prototype-defaults");
  assert.deepEqual(configuration.scoreBands, {
    quarantineBelow: 50,
    restrictedBelow: 65,
    conditionalBelow: 80,
    maximum: 100,
  });
  assert.equal(rule(data, "profile:read").minimumScore, 55);
  assert.equal(rule(data, "profile:read").stepUpRequired, false);
  assert.equal(rule(data, "admin-key:rotate").minimumScore, 90);
  assert.equal(rule(data, "admin-key:rotate").stepUpRequired, true);
  assert.equal(configuration.actionRules.length, ADAPTIVE_AUTHORIZATION_POLICY.actions.length);
  assert.ok(Object.isFrozen(data));
  assert.ok(Object.isFrozen(configuration.actionRules[0]));
});

test("tenant policy versions may become stricter without changing canonical sensitivities", () => {
  const data = mutableDefault();
  rule(data, "profile:read").minimumScore = 60;
  rule(data, "record:read").stepUpRequired = true;

  const validated = validateAdaptiveAuthorizationPolicyData(data, alpha);
  assert.equal(rule(validated, "profile:read").minimumScore, 60);
  assert.equal(rule(validated, "record:read").stepUpRequired, true);
  assert.ok(Object.isFrozen(validated));
});

test("configuration cannot cross tenants, weaken mandatory step-up or downgrade sensitivity", () => {
  assert.throws(
    () => validateAdaptiveAuthorizationPolicyData(mutableDefault(), beta),
    (error) => error instanceof AdaptiveAuthorizationPolicyError
      && error.reasonCode === "POLICY_CONFIGURATION_INVALID",
  );

  const noStepUp = mutableDefault();
  rule(noStepUp, "admin-key:rotate").stepUpRequired = false;
  assert.throws(
    () => validateAdaptiveAuthorizationPolicyData(noStepUp, alpha),
    (error) => error.reasonCode === "POLICY_ACTION_RULE_INVALID",
  );

  const downgraded = mutableDefault();
  rule(downgraded, "admin-key:rotate").sensitivity = "confidential";
  assert.throws(
    () => validateAdaptiveAuthorizationPolicyData(downgraded, alpha),
    (error) => error.reasonCode === "POLICY_ACTION_RULE_INVALID",
  );
});

test("score bands must be ordered and every supported action must have one unique rule", () => {
  const overlapping = mutableDefault();
  overlapping.tenant_trust_policy.authorization.configuration.scoreBands.restrictedBelow = 49;
  assert.throws(
    () => validateAdaptiveAuthorizationPolicyData(overlapping, alpha),
    (error) => error.reasonCode === "POLICY_SCORE_BANDS_INVALID",
  );

  const duplicate = mutableDefault();
  duplicate.tenant_trust_policy.authorization.configuration.actionRules[1].action = "profile:read";
  assert.throws(
    () => validateAdaptiveAuthorizationPolicyData(duplicate, alpha),
    (error) => error.reasonCode === "POLICY_ACTION_RULE_INVALID",
  );
});
