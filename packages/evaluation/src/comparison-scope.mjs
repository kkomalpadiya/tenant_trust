import {
  ACTIONS,
  AUTHORIZATION_MODE_IDS,
  RESOURCE_SENSITIVITY,
  RESOURCE_TYPES,
} from "@tenant-trust/authorization";

export const JWT_RBAC_BASELINE_MODE_ID = "jwt-rbac-baseline-v1";
export const COMPARISON_WORKLOAD_ID = "tenant-trust-comparison-workload-v1";

export const EVALUATION_IDS = Object.freeze({
  alphaTenant: "tnt_018f1234-5678-7abc-8def-0123456789ab",
  betaTenant: "tnt_018f1234-5678-7abc-8def-0123456789ac",
  alice: "sub_018f1234-5678-7abc-8def-0123456789ab",
  alphaAdmin: "sub_018f1234-5678-7abc-8def-0123456789ac",
  bob: "sub_018f1234-5678-7abc-8def-0123456789ad",
  betaAdmin: "sub_018f1234-5678-7abc-8def-0123456789ae",
});

const ids = EVALUATION_IDS;

export const EVALUATION_TENANTS = Object.freeze([
  Object.freeze({ tenantId: ids.alphaTenant, slug: "tenant-alpha" }),
  Object.freeze({ tenantId: ids.betaTenant, slug: "tenant-beta" }),
]);

export const EVALUATION_SUBJECTS = Object.freeze([
  Object.freeze({ subjectId: ids.alice, tenantId: ids.alphaTenant, role: "tenant-member" }),
  Object.freeze({ subjectId: ids.alphaAdmin, tenantId: ids.alphaTenant, role: "tenant-admin" }),
  Object.freeze({ subjectId: ids.bob, tenantId: ids.betaTenant, role: "tenant-member" }),
  Object.freeze({ subjectId: ids.betaAdmin, tenantId: ids.betaTenant, role: "tenant-admin" }),
]);

function resource(resourceId, resourceType, tenantId, ownerSubjectId) {
  return Object.freeze({ resourceId, resourceType, tenantId, ownerSubjectId });
}

export const EVALUATION_RESOURCES = Object.freeze({
  aliceProfile: resource("prf_018f1234-5678-7abc-8def-0123456789a1", "subject-profile", ids.alphaTenant, ids.alice),
  alphaMemberRecord: resource("res_018f1234-5678-7abc-8def-0123456789b0", "tenant-record", ids.alphaTenant, ids.alice),
  alphaAdminRecord: resource("res_018f1234-5678-7abc-8def-0123456789b1", "tenant-record", ids.alphaTenant, ids.alphaAdmin),
  betaMemberRecord: resource("res_018f1234-5678-7abc-8def-0123456789b2", "tenant-record", ids.betaTenant, ids.bob),
  betaAdminRecord: resource("res_018f1234-5678-7abc-8def-0123456789b3", "tenant-record", ids.betaTenant, ids.betaAdmin),
  alphaExport: resource("exp_018f1234-5678-7abc-8def-0123456789c1", "tenant-record-export", ids.alphaTenant, ids.alphaAdmin),
  betaExport: resource("exp_018f1234-5678-7abc-8def-0123456789c2", "tenant-record-export", ids.betaTenant, ids.betaAdmin),
  alphaMembership: resource("adm_018f1234-5678-7abc-8def-0123456789d1", "tenant-administration", ids.alphaTenant, ids.alice),
  betaMembership: resource("adm_018f1234-5678-7abc-8def-0123456789d2", "tenant-administration", ids.betaTenant, ids.bob),
});

function workload(workloadCaseId, actorSubjectId, action, resourceKey, expectedJwtOutcome, expectedJwtReason) {
  return Object.freeze({
    workloadCaseId,
    actorSubjectId,
    action,
    resourceKey,
    expectedJwtOutcome,
    expectedJwtReason,
  });
}

export const EVALUATION_WORKLOAD = Object.freeze([
  workload("alpha-member-self-profile", ids.alice, "profile:read", "aliceProfile", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-member-own-record-read", ids.alice, "record:read", "alphaMemberRecord", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-member-own-record-write", ids.alice, "record:write", "alphaMemberRecord", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-member-peer-record-read", ids.alice, "record:read", "alphaAdminRecord", "deny", "RESOURCE_SCOPE_DENIED"),
  workload("alpha-member-export", ids.alice, "record:export", "alphaExport", "deny", "ROLE_NOT_ELIGIBLE"),
  workload("alpha-admin-tenant-record-read", ids.alphaAdmin, "record:read", "alphaMemberRecord", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-admin-tenant-record-write", ids.alphaAdmin, "record:write", "alphaMemberRecord", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-admin-export", ids.alphaAdmin, "record:export", "alphaExport", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-admin-membership-admin", ids.alphaAdmin, "tenant:admin", "alphaMembership", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("alpha-admin-cross-tenant-read", ids.alphaAdmin, "record:read", "betaMemberRecord", "deny", "RESOURCE_SCOPE_DENIED"),
  workload("beta-admin-tenant-record-read", ids.betaAdmin, "record:read", "betaMemberRecord", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("beta-admin-export", ids.betaAdmin, "record:export", "betaExport", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("beta-admin-membership-admin", ids.betaAdmin, "tenant:admin", "betaMembership", "allow", "RBAC_ROLE_SCOPE_ALLOW"),
  workload("beta-admin-cross-tenant-read", ids.betaAdmin, "record:read", "alphaMemberRecord", "deny", "RESOURCE_SCOPE_DENIED"),
]);

export const EVALUATION_COMPARISON_SCOPE = Object.freeze({
  workloadId: COMPARISON_WORKLOAD_ID,
  tenantIds: Object.freeze(EVALUATION_TENANTS.map(({ tenantId }) => tenantId)),
  subjectIds: Object.freeze(EVALUATION_SUBJECTS.map(({ subjectId }) => subjectId)),
  resourceKeys: Object.freeze(Object.keys(EVALUATION_RESOURCES)),
  actions: ACTIONS,
  resourceTypes: RESOURCE_TYPES,
  resourceSensitivity: RESOURCE_SENSITIVITY,
  modes: Object.freeze([
    Object.freeze({
      label: "Baseline A",
      modeId: JWT_RBAC_BASELINE_MODE_ID,
      identity: "signed-jwt",
      workloadId: COMPARISON_WORKLOAD_ID,
    }),
    Object.freeze({
      label: "Baseline B",
      modeId: AUTHORIZATION_MODE_IDS.PKI_RBAC_BASELINE,
      identity: "tenant-scoped-x509",
      workloadId: COMPARISON_WORKLOAD_ID,
    }),
    Object.freeze({
      label: "Proposed framework",
      modeId: AUTHORIZATION_MODE_IDS.ADAPTIVE_TRUST_OPA,
      identity: "tenant-scoped-x509-plus-adaptive-trust",
      workloadId: COMPARISON_WORKLOAD_ID,
    }),
  ]),
});
