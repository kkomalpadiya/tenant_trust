import { createHash } from "node:crypto";
import { createSlide14PrototypePolicyData } from "@tenant-trust/policy";
import { calculateWeightedTrustScore, initializeTrustControlState } from "@tenant-trust/trust";
import { TRUST_COMPONENT_DEFINITIONS } from "@tenant-trust/trust-model";
import { getReviewPersona, personas, resolveReviewContext, reviewIds } from "./demo-domain.mjs";

const STALE_AFTER_SECONDS = 3_600;

const subjectDefinitions = Object.freeze([
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alice,
    displayName: personas["alpha-member"].displayName,
    initials: personas["alpha-member"].initials,
    role: "tenant-member",
    roleLabel: "Tenant member",
    transitions: Object.freeze([
      Object.freeze({
        ageSeconds: 14_400,
        trigger: "Initial five-signal snapshot",
        reasonCode: "TRUST_STATE_INITIALIZED",
        action: "profile:read",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 82, device: 80, behaviour: 76, certificate: 100, compliance: 86 }),
      }),
      Object.freeze({
        ageSeconds: 7_200,
        trigger: "Behaviour anomaly reduced trust",
        reasonCode: "TRUST_DETERIORATED",
        action: "record:write",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 65, device: 58, behaviour: 35, certificate: 100, compliance: 70 }),
      }),
      Object.freeze({
        ageSeconds: 600,
        trigger: "Corroborated recovery completed",
        reasonCode: "TRUST_RECOVERY_COMPLETED",
        action: "record:read",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 90, device: 84, behaviour: 72, certificate: 100, compliance: 92 }),
      }),
    ]),
  }),
  Object.freeze({
    tenantId: reviewIds.alphaTenant,
    subjectId: reviewIds.alphaAdmin,
    displayName: personas["alpha-admin"].displayName,
    initials: personas["alpha-admin"].initials,
    role: "tenant-admin",
    roleLabel: "Tenant administrator",
    transitions: Object.freeze([
      Object.freeze({
        ageSeconds: 10_800,
        trigger: "Administrator baseline established",
        reasonCode: "TRUST_STATE_INITIALIZED",
        action: "record:export",
        stepUpSatisfied: true,
        components: Object.freeze({ identity: 94, device: 90, behaviour: 86, certificate: 100, compliance: 96 }),
      }),
      Object.freeze({
        ageSeconds: 900,
        trigger: "Fresh device posture confirmed",
        reasonCode: "TRUST_SCORE_INCREASED",
        action: "admin-key:rotate",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 95, device: 94, behaviour: 88, certificate: 100, compliance: 97 }),
      }),
    ]),
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.bob,
    displayName: "Bob Patel",
    initials: "BP",
    role: "tenant-member",
    roleLabel: "Tenant member",
    transitions: Object.freeze([
      Object.freeze({
        ageSeconds: 9_000,
        trigger: "Initial five-signal snapshot",
        reasonCode: "TRUST_STATE_INITIALIZED",
        action: "record:read",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 76, device: 70, behaviour: 68, certificate: 100, compliance: 72 }),
      }),
      Object.freeze({
        ageSeconds: 1_200,
        trigger: "Account-takeover pattern detected",
        reasonCode: "TRUST_DETERIORATED",
        action: "record:read",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 52, device: 44, behaviour: 18, certificate: 100, compliance: 58 }),
      }),
    ]),
  }),
  Object.freeze({
    tenantId: reviewIds.betaTenant,
    subjectId: reviewIds.betaAdmin,
    displayName: personas["beta-admin"].displayName,
    initials: personas["beta-admin"].initials,
    role: "tenant-admin",
    roleLabel: "Tenant administrator",
    transitions: Object.freeze([
      Object.freeze({
        ageSeconds: 12_000,
        trigger: "Administrator baseline established",
        reasonCode: "TRUST_STATE_INITIALIZED",
        action: "tenant:admin",
        stepUpSatisfied: true,
        components: Object.freeze({ identity: 91, device: 86, behaviour: 82, certificate: 100, compliance: 90 }),
      }),
      Object.freeze({
        ageSeconds: 1_500,
        trigger: "Recent behaviour signal evaluated",
        reasonCode: "TRUST_SCORE_DECREASED",
        action: "record:export",
        stepUpSatisfied: false,
        components: Object.freeze({ identity: 90, device: 82, behaviour: 70, certificate: 100, compliance: 88 }),
      }),
    ]),
  }),
]);

function requireDate(value) {
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError("A valid dashboard clock is required.");
  return date;
}

function id(prefix, sequence) {
  return `${prefix}_018f1234-5678-7abc-8def-${String(sequence).padStart(12, "0")}`;
}

function policyForTenant(tenantId) {
  const configuration = createSlide14PrototypePolicyData({ tenantId })
    .tenant_trust_policy.authorization.configuration;
  const alpha = tenantId === reviewIds.alphaTenant;
  const bundleVersion = alpha ? 3 : 2;
  return Object.freeze({
    policyVersionId: id("pol", alpha ? 101 : 201),
    bundleVersion,
    bundleHashSha256: createHash("sha256")
      .update(JSON.stringify({ tenantId, bundleVersion, configuration }), "utf8")
      .digest("hex"),
    profile: configuration.policyProfile,
    calibrationStatus: configuration.calibrationStatus,
    scoreBands: configuration.scoreBands,
    actionRules: configuration.actionRules,
  });
}

function evaluateDecision({ subject, transition, policy, freshnessState }) {
  const rule = policy.actionRules.find(({ action }) => action === transition.action);
  if (freshnessState !== "fresh") return { outcome: "DENY", reasonCode: "TRUST_STATE_STALE", rule };
  if (!rule.roles.includes(subject.role)) return { outcome: "DENY", reasonCode: "ROLE_NOT_ELIGIBLE", rule };
  if (transition.score < policy.scoreBands.quarantineBelow) {
    return { outcome: "QUARANTINE", reasonCode: "TRUST_SCORE_QUARANTINE", rule };
  }
  if (transition.score < rule.minimumScore) {
    return { outcome: "DENY", reasonCode: "TRUST_SCORE_BELOW_ACTION_MINIMUM", rule };
  }
  if (rule.stepUpRequired && !transition.stepUpSatisfied) {
    return { outcome: "STEP_UP", reasonCode: "STEP_UP_REQUIRED", rule };
  }
  return { outcome: "ALLOW", reasonCode: "POLICY_ALLOW", rule };
}

const runtimeAdjustments = Object.freeze({
  "cross-tenant-record": Object.freeze({ identity: -12, device: -5, behaviour: -30, compliance: -15 }),
  "forged-identity-header": Object.freeze({ identity: -18, device: -10, behaviour: -40, compliance: -20 }),
  "sensitive-export": Object.freeze({ identity: -5, behaviour: -20, compliance: -12 }),
  "revoked-certificate": Object.freeze({ identity: -10, behaviour: -10, certificate: -100 }),
  "same-tenant-record": Object.freeze({ identity: -10, behaviour: -10, certificate: -100 }),
});

function runtimeTransitionDefinitions(subject, observations) {
  let components = { ...subject.transitions.at(-1).components };
  return observations.map((observation) => {
    const certificateRejected = observation.reasonCode === "CERTIFICATE_NOT_ACCEPTED";
    const adjustments = certificateRejected
      ? runtimeAdjustments["revoked-certificate"]
      : runtimeAdjustments[observation.scenarioId] ?? Object.freeze({ behaviour: -10 });
    components = Object.fromEntries(Object.entries(components).map(([component, value]) => [
      component,
      Math.max(0, Math.min(100, value + (adjustments[component] ?? 0))),
    ]));
    return Object.freeze({
      observedAt: observation.observedAt,
      trigger: certificateRejected
        ? "Invalid certificate use reduced trust"
        : "Denied access attempt reduced trust",
      reasonCode: certificateRejected
        ? "CERTIFICATE_REJECTION_EVIDENCE"
        : "SUSPICIOUS_ACCESS_EVIDENCE",
      action: observation.action,
      stepUpSatisfied: false,
      components: Object.freeze({ ...components }),
    });
  });
}

function buildSubject(subject, anchor, now, subjectIndex, observations = []) {
  const policy = policyForTenant(subject.tenantId);
  const definitions = [
    ...subject.transitions,
    ...runtimeTransitionDefinitions(subject, observations),
  ];
  const transitions = definitions.map((definition, transitionIndex) => {
    const calculation = calculateWeightedTrustScore(definition.components);
    const controlState = initializeTrustControlState(calculation.score);
    const observedAt = definition.observedAt
      ? requireDate(definition.observedAt)
      : new Date(anchor.getTime() - definition.ageSeconds * 1000);
    return {
      transitionId: id("trn", subjectIndex * 10 + transitionIndex + 1),
      updateVersion: transitionIndex + 1,
      modelVersion: calculation.modelVersion,
      configurationVersion: 1,
      observedAt: observedAt.toISOString(),
      evaluatedAt: new Date(observedAt.getTime() + 2_000).toISOString(),
      score: calculation.score,
      band: controlState.band,
      trigger: definition.trigger,
      reasonCode: definition.reasonCode,
      action: definition.action,
      stepUpSatisfied: definition.stepUpSatisfied,
      calculation,
    };
  });
  const current = transitions.at(-1);
  const ageSeconds = Math.max(0, (now.getTime() - Date.parse(current.observedAt)) / 1000);
  const freshnessState = ageSeconds <= STALE_AFTER_SECONDS ? "fresh" : "stale";
  const history = transitions.map((transition, index) => ({
    transitionId: transition.transitionId,
    updateVersion: transition.updateVersion,
    observedAt: transition.observedAt,
    previousScore: index === 0 ? null : transitions[index - 1].score,
    newScore: transition.score,
    previousBand: index === 0 ? "uninitialized" : transitions[index - 1].band,
    newBand: transition.band,
    trigger: transition.trigger,
    reasonCode: transition.reasonCode,
    modelVersion: transition.modelVersion,
    configurationVersion: transition.configurationVersion,
  })).reverse();
  const decisions = transitions.map((transition, index) => {
    const decision = evaluateDecision({
      subject,
      transition,
      policy,
      freshnessState: index === transitions.length - 1 ? freshnessState : "fresh",
    });
    return {
      decisionId: id("dec", subjectIndex * 10 + index + 1),
      correlationId: id("cor", subjectIndex * 10 + index + 1),
      evaluatedAt: transition.evaluatedAt,
      action: transition.action,
      outcome: decision.outcome,
      reasonCodes: Object.freeze([decision.reasonCode]),
      trustScore: transition.score,
      trustBand: transition.band,
      minimumScore: decision.rule.minimumScore,
      stepUpRequired: decision.rule.stepUpRequired,
      policyVersionId: policy.policyVersionId,
      bundleVersion: policy.bundleVersion,
      transitionId: transition.transitionId,
    };
  }).reverse();
  const components = TRUST_COMPONENT_DEFINITIONS.map((definition) => {
    const contribution = current.calculation.contributions[definition.id];
    return {
      id: definition.id,
      label: definition.label,
      meaning: definition.meaning,
      value: contribution.normalizedValue,
      weight: contribution.weight,
      weightedContribution: contribution.weightedContribution,
    };
  });

  return Object.freeze({
    tenantId: subject.tenantId,
    subjectId: subject.subjectId,
    displayName: subject.displayName,
    initials: subject.initials,
    role: subject.role,
    roleLabel: subject.roleLabel,
    current: Object.freeze({
      lastKnownScore: current.score,
      policyScore: freshnessState === "fresh" ? current.score : null,
      band: current.band,
      transitionId: current.transitionId,
      updateVersion: current.updateVersion,
      modelVersion: current.modelVersion,
      configurationVersion: current.configurationVersion,
      observedAt: current.observedAt,
    }),
    freshness: Object.freeze({
      state: freshnessState,
      usableForPolicy: freshnessState === "fresh",
      reasonCode: freshnessState === "fresh" ? null : "TRUST_STATE_STALE",
      ageSeconds,
      staleAfterSeconds: STALE_AFTER_SECONDS,
    }),
    policy: Object.freeze({
      policyVersionId: policy.policyVersionId,
      bundleVersion: policy.bundleVersion,
      bundleHashSha256: policy.bundleHashSha256,
      profile: policy.profile,
      calibrationStatus: policy.calibrationStatus,
    }),
    components: Object.freeze(components),
    transitions: Object.freeze(history),
    decisions: Object.freeze(decisions),
  });
}

export function createTrustDashboard({ clock = () => new Date() } = {}) {
  if (typeof clock !== "function") throw new TypeError("Trust dashboard clock must be a function.");
  const anchor = requireDate(clock());
  const observationsBySubject = new Map();

  function getState(personaKey = "alpha-member") {
    const persona = getReviewPersona(personaKey);
    const context = resolveReviewContext(personaKey);
    const now = requireDate(clock());
    const visibleDefinitions = subjectDefinitions.filter((subject) => (
      subject.tenantId === context.tenantId
      && (subject.subjectId === context.subjectId || context.roles.includes("tenant-admin"))
    ));
    const trustSubjects = visibleDefinitions.map((subject) => buildSubject(
      subject,
      anchor,
      now,
      subjectDefinitions.indexOf(subject) + 1,
      observationsBySubject.get(subject.subjectId) ?? [],
    ));
    const currentSubject = trustSubjects.find(({ subjectId }) => subjectId === persona.subjectId)
      ?? trustSubjects[0]
      ?? null;
    return Object.freeze({
      trustSubjects: Object.freeze(trustSubjects),
      trustSummary: Object.freeze({
        subjectCount: trustSubjects.length,
        freshCount: trustSubjects.filter(({ freshness }) => freshness.state === "fresh").length,
        decisionCount: trustSubjects.reduce((total, subject) => total + subject.decisions.length, 0),
        currentSubjectId: currentSubject?.subjectId ?? null,
        policyVersionId: currentSubject?.policy.policyVersionId ?? null,
        bundleVersion: currentSubject?.policy.bundleVersion ?? null,
      }),
    });
  }

  function recordScenario({ personaKey = "alpha-member", result } = {}) {
    if (!result || result.outcome !== "deny") return null;
    const persona = getReviewPersona(personaKey);
    const previous = getState(personaKey).trustSubjects
      .find(({ subjectId }) => subjectId === persona.subjectId)?.current;
    const observations = observationsBySubject.get(persona.subjectId) ?? [];
    observations.push(Object.freeze({
      observedAt: requireDate(clock()).toISOString(),
      scenarioId: result.scenarioId,
      action: result.event.action,
      reasonCode: result.reasonCode,
    }));
    observationsBySubject.set(persona.subjectId, observations);
    const current = getState(personaKey).trustSubjects
      .find(({ subjectId }) => subjectId === persona.subjectId)?.current;
    if (!previous || !current) return null;
    return Object.freeze({
      previousScore: previous.lastKnownScore,
      newScore: current.lastKnownScore,
      previousBand: previous.band,
      newBand: current.band,
      reasonCode: result.reasonCode === "CERTIFICATE_NOT_ACCEPTED"
        ? "CERTIFICATE_REJECTION_EVIDENCE"
        : "SUSPICIOUS_ACCESS_EVIDENCE",
    });
  }

  return Object.freeze({ getState, recordScenario });
}
