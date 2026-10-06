import assert from "node:assert/strict";
import { test } from "node:test";
import {
  INITIAL_TRUST_MODEL_CONFIGURATION,
  INITIAL_TRUST_WEIGHTS,
  NORMALIZED_COMPONENT_RANGE,
  TRUST_COMPONENT_DEFINITIONS,
  TRUST_COMPONENT_IDS,
  TrustModelDefinitionError,
  defineNormalizedComponents,
  defineTrustModelConfiguration,
} from "../src/index.mjs";

const expectedComponentIds = [
  "identity",
  "device",
  "behaviour",
  "certificate",
  "compliance",
];

const expectedInitialWeights = {
  identity: 0.20,
  device: 0.25,
  behaviour: 0.25,
  certificate: 0.15,
  compliance: 0.15,
};

test("defines the five canonical normalized components in stable order", () => {
  assert.deepEqual(TRUST_COMPONENT_IDS, expectedComponentIds);
  assert.deepEqual(NORMALIZED_COMPONENT_RANGE, {
    minimum: 0,
    maximum: 100,
    direction: "higher-is-more-trusted",
  });
  assert.deepEqual(
    TRUST_COMPONENT_DEFINITIONS.map(({ id, evidenceType, normalizedRange }) => ({
      id,
      evidenceType,
      normalizedRange,
    })),
    expectedComponentIds.map((id) => ({
      id,
      evidenceType: id,
      normalizedRange: NORMALIZED_COMPONENT_RANGE,
    })),
  );
  assert.ok(Object.isFrozen(TRUST_COMPONENT_IDS));
  assert.ok(Object.isFrozen(TRUST_COMPONENT_DEFINITIONS));
  assert.ok(TRUST_COMPONENT_DEFINITIONS.every(Object.isFrozen));
});

test("publishes the slide 13 weights as immutable uncalibrated defaults", () => {
  assert.deepEqual(INITIAL_TRUST_WEIGHTS, expectedInitialWeights);
  assert.equal(Object.values(INITIAL_TRUST_WEIGHTS).reduce((total, weight) => total + weight, 0), 1);
  assert.deepEqual(INITIAL_TRUST_MODEL_CONFIGURATION, {
    modelVersion: "1.0.0",
    weights: expectedInitialWeights,
  });
  assert.ok(Object.isFrozen(INITIAL_TRUST_WEIGHTS));
  assert.ok(Object.isFrozen(INITIAL_TRUST_MODEL_CONFIGURATION));
});

test("accepts complete normalized component vectors including both boundaries", () => {
  const values = defineNormalizedComponents({
    identity: 0,
    device: 25.5,
    behaviour: 50,
    certificate: 75.25,
    compliance: 100,
  });
  assert.deepEqual(values, {
    identity: 0,
    device: 25.5,
    behaviour: 50,
    certificate: 75.25,
    compliance: 100,
  });
  assert.deepEqual(Object.keys(values), expectedComponentIds);
  assert.ok(Object.isFrozen(values));
});

test("rejects missing, unknown, non-finite and out-of-range component values", () => {
  const valid = {
    identity: 50,
    device: 50,
    behaviour: 50,
    certificate: 50,
    compliance: 50,
  };
  for (const candidate of [
    { ...valid, compliance: undefined },
    Object.fromEntries(Object.entries(valid).slice(0, -1)),
    { ...valid, unexpected: 50 },
    { ...valid, identity: Number.NaN },
    { ...valid, device: Number.POSITIVE_INFINITY },
    { ...valid, behaviour: -0.01 },
    { ...valid, certificate: 100.01 },
    { ...valid, compliance: "100" },
  ]) {
    assert.throws(
      () => defineNormalizedComponents(candidate),
      (error) => error instanceof TrustModelDefinitionError,
    );
  }
});

test("supports a complete tenant-tuned weight set without mutating the defaults", () => {
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
  assert.deepEqual(tuned, {
    modelVersion: "1.1.0",
    weights: {
      identity: 0.25,
      device: 0.20,
      behaviour: 0.20,
      certificate: 0.20,
      compliance: 0.15,
    },
  });
  assert.ok(Object.isFrozen(tuned));
  assert.ok(Object.isFrozen(tuned.weights));
  assert.deepEqual(INITIAL_TRUST_WEIGHTS, expectedInitialWeights);
});

test("configuration validation requires semantic versioning, exact keys and a unit weight total", () => {
  const validWeights = { ...expectedInitialWeights };
  for (const candidate of [
    null,
    { modelVersion: "1", weights: validWeights },
    { modelVersion: "v1.0.0", weights: validWeights },
    { modelVersion: "1.0.0", weights: { ...validWeights, identity: -0.01, compliance: 0.36 } },
    { modelVersion: "1.0.0", weights: { ...validWeights, identity: 1.01, compliance: -0.01 } },
    { modelVersion: "1.0.0", weights: { ...validWeights, identity: 0.19 } },
    { modelVersion: "1.0.0", weights: { ...validWeights, identity: "0.20" } },
    { modelVersion: "1.0.0", weights: { ...validWeights, unexpected: 0 } },
    { modelVersion: "1.0.0", weights: Object.fromEntries(Object.entries(validWeights).slice(0, -1)) },
    { modelVersion: "1.0.0", weights: validWeights, initialScore: 60 },
  ]) {
    assert.throws(
      () => defineTrustModelConfiguration(candidate),
      (error) => error instanceof TrustModelDefinitionError,
    );
  }
});

test("the published default passes the same validator as tenant-tuned configurations", () => {
  assert.deepEqual(defineTrustModelConfiguration(), INITIAL_TRUST_MODEL_CONFIGURATION);
});
