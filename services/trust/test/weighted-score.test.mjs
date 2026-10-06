import assert from "node:assert/strict";
import { test } from "node:test";
import { TrustModelDefinitionError } from "@tenant-trust/trust-model";
import {
  WEIGHTED_SCORE_METHOD,
  WEIGHTED_SCORE_NORMALIZATION,
  WEIGHTED_SCORE_ROUNDING,
  calculateWeightedTrustScore,
} from "../src/index.mjs";

const components = Object.freeze({
  identity: 90,
  device: 80,
  behaviour: 70,
  certificate: 100,
  compliance: 60,
});

test("matches a hand-calculated score using the published default weights", () => {
  const result = calculateWeightedTrustScore(components);

  assert.equal(result.score, 79.5);
  assert.equal(result.modelVersion, "1.0.0");
  assert.equal(result.method, WEIGHTED_SCORE_METHOD);
  assert.deepEqual(result.contributions, {
    identity: { normalizedValue: 90, weight: 0.20, weightedContribution: 18 },
    device: { normalizedValue: 80, weight: 0.25, weightedContribution: 20 },
    behaviour: { normalizedValue: 70, weight: 0.25, weightedContribution: 17.5 },
    certificate: { normalizedValue: 100, weight: 0.15, weightedContribution: 15 },
    compliance: { normalizedValue: 60, weight: 0.15, weightedContribution: 9 },
  });
});

test("keeps the weighted score inside both normalized boundaries", () => {
  const zero = calculateWeightedTrustScore(Object.fromEntries(
    Object.keys(components).map((componentId) => [componentId, 0]),
  ));
  const hundred = calculateWeightedTrustScore(Object.fromEntries(
    Object.keys(components).map((componentId) => [componentId, 100]),
  ));

  assert.equal(zero.score, 0);
  assert.equal(hundred.score, 100);
  assert.deepEqual(zero.scoreRange, {
    minimum: 0,
    maximum: 100,
    direction: "higher-is-more-trusted",
  });
});

test("uses a complete tenant-tuned configuration without changing its inputs", () => {
  const tuned = {
    modelVersion: "1.1.0",
    weights: {
      identity: 0.10,
      device: 0.20,
      behaviour: 0.30,
      certificate: 0.25,
      compliance: 0.15,
    },
  };
  const componentsBefore = structuredClone(components);
  const tunedBefore = structuredClone(tuned);
  const result = calculateWeightedTrustScore(components, tuned);

  assert.equal(result.score, 80);
  assert.equal(result.modelVersion, "1.1.0");
  assert.deepEqual(components, componentsBefore);
  assert.deepEqual(tuned, tunedBefore);
});

test("applies exact decimal products and one documented half-up score rounding", () => {
  const result = calculateWeightedTrustScore({
    identity: 33.335,
    device: 33.335,
    behaviour: 33.335,
    certificate: 33.335,
    compliance: 33.335,
  });

  assert.equal(result.score, 33.34);
  assert.deepEqual(result.rounding, {
    scoreDecimalPlaces: 2,
    contributionDecimalPlaces: 6,
    mode: "half-up",
  });
  assert.deepEqual(
    Object.values(result.contributions).map(({ weightedContribution }) => weightedContribution),
    [6.667, 8.33375, 8.33375, 5.00025, 5.00025],
  );
});

test("explains that validated 0-100 inputs pass through identity normalization", () => {
  const result = calculateWeightedTrustScore(components);

  assert.equal(result.normalization, WEIGHTED_SCORE_NORMALIZATION);
  assert.deepEqual(result.normalization, {
    method: "identity",
    range: {
      minimum: 0,
      maximum: 100,
      direction: "higher-is-more-trusted",
    },
  });
  assert.equal(result.rounding, WEIGHTED_SCORE_ROUNDING);
});

test("returns a deeply immutable calculation explanation in canonical component order", () => {
  const result = calculateWeightedTrustScore(components);

  assert.deepEqual(Object.keys(result.contributions), [
    "identity",
    "device",
    "behaviour",
    "certificate",
    "compliance",
  ]);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.components));
  assert.ok(Object.isFrozen(result.weights));
  assert.ok(Object.isFrozen(result.contributions));
  assert.ok(Object.values(result.contributions).every(Object.isFrozen));
  assert.ok(Object.isFrozen(result.normalization));
  assert.ok(Object.isFrozen(result.rounding));
});

test("fails closed on incomplete, unknown, non-finite or out-of-range component inputs", () => {
  for (const candidate of [
    { ...components, compliance: undefined },
    Object.fromEntries(Object.entries(components).slice(0, -1)),
    { ...components, unexpected: 50 },
    { ...components, identity: Number.NaN },
    { ...components, device: Number.POSITIVE_INFINITY },
    { ...components, behaviour: -0.01 },
    { ...components, certificate: 100.01 },
  ]) {
    assert.throws(
      () => calculateWeightedTrustScore(candidate),
      (error) => error instanceof TrustModelDefinitionError,
    );
  }
});

test("fails closed on malformed model versions, weights and weight totals", () => {
  const validWeights = {
    identity: 0.20,
    device: 0.25,
    behaviour: 0.25,
    certificate: 0.15,
    compliance: 0.15,
  };
  for (const configuration of [
    { modelVersion: "v1", weights: validWeights },
    { modelVersion: "1.0.0", weights: { ...validWeights, compliance: 0.14 } },
    { modelVersion: "1.0.0", weights: { ...validWeights, identity: -0.01, compliance: 0.36 } },
    { modelVersion: "1.0.0", weights: { ...validWeights, unexpected: 0 } },
  ]) {
    assert.throws(
      () => calculateWeightedTrustScore(components, configuration),
      (error) => error instanceof TrustModelDefinitionError,
    );
  }
});
