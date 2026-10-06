import assert from "node:assert/strict";
import {
  INITIAL_TRUST_MODEL_CONFIGURATION,
  INITIAL_TRUST_WEIGHTS,
  TRUST_COMPONENT_DEFINITIONS,
  TRUST_COMPONENT_IDS,
  TrustModelDefinitionError,
  defineNormalizedComponents,
  defineTrustModelConfiguration,
} from "../packages/trust-model/src/index.mjs";

assert.deepEqual(TRUST_COMPONENT_IDS, [
  "identity",
  "device",
  "behaviour",
  "certificate",
  "compliance",
]);
assert.deepEqual(
  TRUST_COMPONENT_DEFINITIONS.map(({ id, evidenceType, normalizedRange }) => ({
    id,
    evidenceType,
    normalizedRange,
  })),
  TRUST_COMPONENT_IDS.map((id) => ({
    id,
    evidenceType: id,
    normalizedRange: {
      minimum: 0,
      maximum: 100,
      direction: "higher-is-more-trusted",
    },
  })),
);
console.log("PASS five evidence-aligned trust components use one 0-100 higher-is-more-trusted scale");

assert.deepEqual(INITIAL_TRUST_WEIGHTS, {
  identity: 0.20,
  device: 0.25,
  behaviour: 0.25,
  certificate: 0.15,
  compliance: 0.15,
});
assert.equal(Object.values(INITIAL_TRUST_WEIGHTS).reduce((total, weight) => total + weight, 0), 1);
assert.deepEqual(defineTrustModelConfiguration(), INITIAL_TRUST_MODEL_CONFIGURATION);
console.log("PASS model 1.0.0 publishes the slide 13 weights as immutable unit-sum defaults");

const tuned = defineTrustModelConfiguration({
  modelVersion: "1.1.0",
  weights: {
    identity: 0.25,
    device: 0.20,
    behaviour: 0.20,
    certificate: 0.20,
    compliance: 0.15,
  },
});
assert.equal(Object.values(tuned.weights).reduce((total, weight) => total + weight, 0), 1);
assert.notDeepEqual(tuned.weights, INITIAL_TRUST_WEIGHTS);
assert.deepEqual(INITIAL_TRUST_WEIGHTS, INITIAL_TRUST_MODEL_CONFIGURATION.weights);
console.log("PASS complete tenant-tuned weights validate without changing the initial defaults");

assert.deepEqual(defineNormalizedComponents({
  identity: 0,
  device: 25,
  behaviour: 50,
  certificate: 75,
  compliance: 100,
}), {
  identity: 0,
  device: 25,
  behaviour: 50,
  certificate: 75,
  compliance: 100,
});
for (const operation of [
  () => defineNormalizedComponents({
    identity: 100,
    device: 100,
    behaviour: 100,
    certificate: 100,
  }),
  () => defineNormalizedComponents({
    identity: 100,
    device: 101,
    behaviour: 100,
    certificate: 100,
    compliance: 100,
  }),
  () => defineTrustModelConfiguration({
    modelVersion: "1.0.0",
    weights: {
      identity: 0.20,
      device: 0.25,
      behaviour: 0.25,
      certificate: 0.15,
      compliance: 0.14,
    },
  }),
]) {
  assert.throws(operation, (error) => error instanceof TrustModelDefinitionError);
}
console.log("PASS missing, unknown, non-finite, out-of-range and non-unit inputs fail closed");
