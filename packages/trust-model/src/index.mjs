export const TRUST_COMPONENT_IDS = Object.freeze([
  "identity",
  "device",
  "behaviour",
  "certificate",
  "compliance",
]);

export const NORMALIZED_COMPONENT_RANGE = Object.freeze({
  minimum: 0,
  maximum: 100,
  direction: "higher-is-more-trusted",
});

export const INITIAL_TRUST_WEIGHTS = Object.freeze({
  identity: 0.20,
  device: 0.25,
  behaviour: 0.25,
  certificate: 0.15,
  compliance: 0.15,
});

function component(id, label, meaning) {
  return Object.freeze({
    id,
    label,
    evidenceType: id,
    normalizedRange: NORMALIZED_COMPONENT_RANGE,
    defaultWeight: INITIAL_TRUST_WEIGHTS[id],
    meaning,
  });
}

export const TRUST_COMPONENT_DEFINITIONS = Object.freeze([
  component("identity", "Identity", "Authentication assurance and authoritative identity state."),
  component("device", "Device", "Managed-device posture and device risk."),
  component("behaviour", "Behaviour", "Observed activity and behaviour risk."),
  component("certificate", "Certificate", "Authoritative certificate lifecycle and status."),
  component("compliance", "Compliance", "Evaluated control and compliance posture."),
]);

export const INITIAL_TRUST_MODEL_CONFIGURATION = Object.freeze({
  modelVersion: "1.0.0",
  weights: INITIAL_TRUST_WEIGHTS,
});

const COMPONENT_ID_SET = new Set(TRUST_COMPONENT_IDS);
const MODEL_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const WEIGHT_TOTAL_TOLERANCE = 1e-12;

export class TrustModelDefinitionError extends Error {
  constructor(reasonCode) {
    super("Trust model definition is invalid.");
    this.name = "TrustModelDefinitionError";
    this.reasonCode = reasonCode;
  }
}

function fail(reasonCode) {
  throw new TrustModelDefinitionError(reasonCode);
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function requireExactComponentKeys(value, invalidReasonCode) {
  if (!isPlainObject(value)) fail(invalidReasonCode);
  const keys = Object.keys(value);
  if (keys.length !== TRUST_COMPONENT_IDS.length
    || keys.some((key) => !COMPONENT_ID_SET.has(key))) {
    fail(invalidReasonCode);
  }
}

export function defineNormalizedComponents(values) {
  requireExactComponentKeys(values, "NORMALIZED_COMPONENTS_INVALID");
  const normalized = {};
  for (const componentId of TRUST_COMPONENT_IDS) {
    const value = values[componentId];
    if (typeof value !== "number"
      || !Number.isFinite(value)
      || value < NORMALIZED_COMPONENT_RANGE.minimum
      || value > NORMALIZED_COMPONENT_RANGE.maximum) {
      fail("NORMALIZED_COMPONENT_VALUE_INVALID");
    }
    normalized[componentId] = value;
  }
  return Object.freeze(normalized);
}

export function defineTrustModelConfiguration(configuration = INITIAL_TRUST_MODEL_CONFIGURATION) {
  if (!isPlainObject(configuration)) fail("TRUST_MODEL_CONFIGURATION_INVALID");
  const keys = Object.keys(configuration);
  if (keys.length !== 2 || !keys.includes("modelVersion") || !keys.includes("weights")) {
    fail("TRUST_MODEL_CONFIGURATION_INVALID");
  }
  if (typeof configuration.modelVersion !== "string"
    || !MODEL_VERSION.test(configuration.modelVersion)) {
    fail("MODEL_VERSION_INVALID");
  }

  requireExactComponentKeys(configuration.weights, "TRUST_WEIGHTS_INVALID");
  const weights = {};
  let total = 0;
  for (const componentId of TRUST_COMPONENT_IDS) {
    const weight = configuration.weights[componentId];
    if (typeof weight !== "number" || !Number.isFinite(weight) || weight < 0 || weight > 1) {
      fail("TRUST_WEIGHT_INVALID");
    }
    weights[componentId] = weight;
    total += weight;
  }
  if (Math.abs(total - 1) > WEIGHT_TOTAL_TOLERANCE) fail("TRUST_WEIGHT_TOTAL_INVALID");

  return Object.freeze({
    modelVersion: configuration.modelVersion,
    weights: Object.freeze(weights),
  });
}
