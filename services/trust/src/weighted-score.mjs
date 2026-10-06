import {
  INITIAL_TRUST_MODEL_CONFIGURATION,
  NORMALIZED_COMPONENT_RANGE,
  TRUST_COMPONENT_IDS,
  defineNormalizedComponents,
  defineTrustModelConfiguration,
} from "@tenant-trust/trust-model";

export const WEIGHTED_SCORE_METHOD = "weighted-arithmetic-mean";

export const WEIGHTED_SCORE_ROUNDING = Object.freeze({
  scoreDecimalPlaces: 2,
  contributionDecimalPlaces: 6,
  mode: "half-up",
});

export const WEIGHTED_SCORE_NORMALIZATION = Object.freeze({
  method: "identity",
  range: NORMALIZED_COMPONENT_RANGE,
});

function decimalParts(value) {
  const match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/u.exec(value.toString().toLowerCase());
  if (!match) throw new TypeError("A finite non-negative decimal value is required.");

  const fraction = match[2] ?? "";
  const exponent = Number(match[3] ?? 0);
  let integer = BigInt(`${match[1]}${fraction}`);
  let scale = fraction.length - exponent;
  if (scale < 0) {
    integer *= 10n ** BigInt(-scale);
    scale = 0;
  }
  return { integer, scale };
}

function multiplyDecimal(left, right) {
  const leftParts = decimalParts(left);
  const rightParts = decimalParts(right);
  return {
    integer: leftParts.integer * rightParts.integer,
    scale: leftParts.scale + rightParts.scale,
  };
}

function sumDecimals(values) {
  const scale = Math.max(...values.map((value) => value.scale));
  return {
    integer: values.reduce(
      (total, value) => total + value.integer * (10n ** BigInt(scale - value.scale)),
      0n,
    ),
    scale,
  };
}

function roundedNumber(value, decimalPlaces) {
  let rounded = value.integer;
  if (value.scale > decimalPlaces) {
    const divisor = 10n ** BigInt(value.scale - decimalPlaces);
    const remainder = rounded % divisor;
    rounded /= divisor;
    if (remainder * 2n >= divisor) rounded += 1n;
  } else if (value.scale < decimalPlaces) {
    rounded *= 10n ** BigInt(decimalPlaces - value.scale);
  }

  if (decimalPlaces === 0) return Number(rounded);
  const digits = rounded.toString().padStart(decimalPlaces + 1, "0");
  const whole = digits.slice(0, -decimalPlaces);
  const fraction = digits.slice(-decimalPlaces);
  return Number(`${whole}.${fraction}`);
}

export function calculateWeightedTrustScore(
  componentValues,
  configuration = INITIAL_TRUST_MODEL_CONFIGURATION,
) {
  const components = defineNormalizedComponents(componentValues);
  const model = defineTrustModelConfiguration(configuration);
  const exactContributions = TRUST_COMPONENT_IDS.map((componentId) =>
    multiplyDecimal(components[componentId], model.weights[componentId]));

  const contributions = Object.freeze(Object.fromEntries(
    TRUST_COMPONENT_IDS.map((componentId, index) => [
      componentId,
      Object.freeze({
        normalizedValue: components[componentId],
        weight: model.weights[componentId],
        weightedContribution: roundedNumber(
          exactContributions[index],
          WEIGHTED_SCORE_ROUNDING.contributionDecimalPlaces,
        ),
      }),
    ]),
  ));

  const score = roundedNumber(
    sumDecimals(exactContributions),
    WEIGHTED_SCORE_ROUNDING.scoreDecimalPlaces,
  );
  if (score < NORMALIZED_COMPONENT_RANGE.minimum
    || score > NORMALIZED_COMPONENT_RANGE.maximum) {
    throw new RangeError("The weighted trust score is outside the normalized range.");
  }

  return Object.freeze({
    modelVersion: model.modelVersion,
    method: WEIGHTED_SCORE_METHOD,
    score,
    scoreRange: NORMALIZED_COMPONENT_RANGE,
    components,
    weights: model.weights,
    contributions,
    normalization: WEIGHTED_SCORE_NORMALIZATION,
    rounding: WEIGHTED_SCORE_ROUNDING,
  });
}
