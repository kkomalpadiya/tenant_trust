const icons = {
  check: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9.2 16.2-4.1-4.1-1.4 1.4 5.5 5.5L21 7.2l-1.4-1.4-10.4 10.4Z"/></svg>',
  close: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7.1 5.7 4.9 4.9 4.9-4.9 1.4 1.4-4.9 4.9 4.9 4.9-1.4 1.4-4.9-4.9-4.9 4.9-1.4-1.4 4.9-4.9-4.9-4.9 1.4-1.4Z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10V8a5 5 0 0 1 10 0v2h2v11H5V10h2Zm2 0h6V8a3 3 0 0 0-6 0v2Zm3 3a2 2 0 0 0-1 3.7V19h2v-2.3a2 2 0 0 0-1-3.7Z"/></svg>',
  document: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 2h8l4 4v16H6V2Zm2 2v16h8V8h-4V4H8Zm2 8h4v2h-4v-2Zm0 4h4v2h-4v-2Z"/></svg>',
  arrow: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m13 5 7 7-7 7-1.4-1.4 4.6-4.6H4v-2h12.2l-4.6-4.6L13 5Z"/></svg>',
  flask: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 3h6v2l-1 1v4.3l4.6 7.1A2.3 2.3 0 0 1 16.7 21H7.3a2.3 2.3 0 0 1-1.9-3.6l4.6-7.1V6L9 5V3Z"/></svg>',
};

const state = {
  activeView: "overview",
  personaKey: "alpha-member",
  data: null,
  auditEvents: [],
  lastResult: null,
  trustSubjectId: null,
};

const pageTitles = {
  overview: "Security overview",
  certificates: "Certificates",
  trust: "Trust decisions",
  records: "Tenant data",
  lab: "Access boundary lab",
  audit: "Audit operations",
};

const dateFormatter = new Intl.DateTimeFormat("en", { day: "2-digit", month: "short", year: "numeric" });
const timeFormatter = new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit" });

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error ?? `Request failed with status ${response.status}`);
    error.reasonCode = payload.error ?? "REQUEST_FAILED";
    error.statusCode = response.status;
    throw error;
  }
  return payload;
}

function setView(view) {
  state.activeView = view;
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  document.querySelectorAll(".view").forEach((section) => section.classList.toggle("active", section.id === `view-${view}`));
  document.querySelector("#page-title").textContent = pageTitles[view];
  window.location.hash = view;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 3000);
}

function metricIcon(kind) {
  const map = {
    phases: '<svg viewBox="0 0 24 24"><path d="M4 4h7v7H4V4Zm9 0h7v7h-7V4ZM4 13h7v7H4v-7Zm9 0h7v7h-7v-7Z"/></svg>',
    tests: '<svg viewBox="0 0 24 24"><path d="M9 3h6v2l-1 1v4.3l4.6 7.1A2.3 2.3 0 0 1 16.7 21H7.3a2.3 2.3 0 0 1-1.9-3.6l4.6-7.1V6L9 5V3Zm2.7 8.4-2.2 3.4h5l-2.2-3.4h-.6Z"/></svg>',
    tenants: '<svg viewBox="0 0 24 24"><path d="M8 3a4 4 0 1 1 0 8 4 4 0 0 1 0-8Zm8 2a3 3 0 1 1 0 6 3 3 0 0 1 0-6ZM2 20a6 6 0 0 1 12 0H2Zm12.2-6.6A5 5 0 0 1 22 17.6V20h-6a8 8 0 0 0-1.8-6.6Z"/></svg>',
    shield: '<svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5.1 3.4 9.4 8 11 4.6-1.6 8-5.9 8-11V5l-8-3Zm-1 14-3.5-3.5 1.4-1.4 2.1 2.1 4.5-4.5 1.4 1.4L11 16Z"/></svg>',
  };
  return map[kind];
}

function renderMetrics(project, certificateSummary) {
  const metrics = [
    { value: `${project.completedPhases}/${project.totalPhases}`, label: "Phases complete", detail: `${project.completedTasks} verified tasks`, kind: "phases", color: "#2f7df4" },
    { value: `${project.completedTasks}/${project.totalTasks}`, label: "Tasks complete", detail: `${project.nextTask} ready`, kind: "tests", color: "#15856c" },
    { value: project.tenantCount, label: "Isolated tenants", detail: "Alpha + Beta", kind: "tenants", color: "#8b5cf6" },
    { value: certificateSummary.permittedOperations, label: "Permitted controls", detail: "Issue + renew + revoke", kind: "shield", color: "#d47d27" },
  ];
  document.querySelector("#metric-grid").innerHTML = metrics.map((metric) => `
    <article class="metric-card" style="--metric-color:${metric.color}">
      <span class="metric-icon">${metricIcon(metric.kind)}</span>
      <div><strong>${metric.value}</strong><span>${metric.label}</span><small>${metric.detail}</small></div>
    </article>
  `).join("");
}

function renderPersona(data) {
  const { persona, certificate, context } = data;
  document.querySelector("#persona-avatar").textContent = persona.initials;
  document.querySelector("#persona-avatar").style.background = `linear-gradient(135deg, ${persona.tenant.color}, #174d92)`;
  document.querySelector("#persona-name").textContent = persona.displayName;
  document.querySelector("#persona-role").textContent = `${persona.roleLabel} · ${persona.tenant.name}`;
  document.querySelector("#first-name").textContent = persona.displayName.split(" ")[0];
  document.querySelector("#intro-tenant").textContent = persona.tenant.name;
  document.querySelector("#certificate-subject").textContent = persona.displayName;
  document.querySelector("#certificate-issuer").textContent = certificate.issuer;
  document.querySelector("#certificate-serial").textContent = certificate.serial;
  document.querySelector("#certificate-expiry").textContent = dateFormatter.format(new Date(certificate.expiresOn));
  document.querySelector("#certificate-fingerprint").textContent = certificate.fingerprint;
  const certificateStatus = document.querySelector("#certificate-status");
  certificateStatus.className = `status-pill ${certificate.state === "active" ? "success" : "danger"}`;
  certificateStatus.innerHTML = `<span></span> ${escapeHtml(certificate.state)}`;
  document.querySelector("#boundary-context").textContent = `Tenant v${context.versions.tenant} · membership v${context.versions.membership}`;
  document.querySelector("#scope-tenant").textContent = persona.tenant.name;
  document.querySelector("#scope-role").textContent = persona.roleLabel;

  const recordDecision = data.actionDecisions.find(({ action }) => action === "record:read");
  document.querySelector("#scope-value").textContent = recordDecision.scope === "tenant" ? "Tenant-wide" : "Owner only";
  const exportDecision = data.actionDecisions.find(({ action }) => action === "record:export");
  const exportButton = document.querySelector("#export-button");
  exportButton.dataset.allowed = exportDecision.outcome === "requires-controls" ? "true" : "false";
  exportButton.title = exportDecision.outcome === "requires-controls" ? "Run the controlled export scenario" : "This role is not eligible for export";
}

function operationReason(reasonCode) {
  const reasons = {
    SELF_ENROLLMENT_ALLOWED: "Self enrollment allowed",
    TENANT_ADMIN_ENROLLMENT_ALLOWED: "Tenant administrator scope",
    SELF_OPERATION_ALLOWED: "Own certificate",
    TENANT_ADMIN_OPERATION_ALLOWED: "Tenant administrator scope",
    RENEWAL_WINDOW_CLOSED: "Renewal window is closed",
    CERTIFICATE_NOT_ACTIVE: "Certificate is not active",
    SUBJECT_ENROLLMENT_UNAUTHORIZED: "Role is not permitted",
    CERTIFICATE_OPERATION_UNAUTHORIZED: "Role is not permitted",
  };
  return reasons[reasonCode] ?? reasonCode.replaceAll("_", " ").toLowerCase();
}

function operationButton({ operation, subjectId, certificateId = "", decision }) {
  const label = operation[0].toUpperCase() + operation.slice(1);
  return `<button class="control-button ${operation}" type="button"
    data-certificate-operation="${operation}"
    data-subject-id="${escapeHtml(subjectId)}"
    data-certificate-id="${escapeHtml(certificateId)}"
    title="${escapeHtml(operationReason(decision.reasonCode))}"
    ${decision.allowed ? "" : "disabled"}>${label}</button>`;
}

function renderCertificateDashboard(data) {
  const summary = data.certificateSummary;
  document.querySelector("#subject-total").textContent = summary.subjectCount;
  document.querySelector("#certificate-total").textContent = summary.certificateCount;
  document.querySelector("#active-certificate-total").textContent = summary.activeCertificateCount;
  document.querySelector("#permitted-operation-total").textContent = summary.permittedOperations;

  document.querySelector("#subject-grid").innerHTML = data.subjects.map((subject) => `
    <article class="subject-card ${subject.isCurrentSubject ? "current" : ""}">
      <span class="subject-avatar">${escapeHtml(subject.initials)}</span>
      <div class="subject-copy">
        <span>${subject.isCurrentSubject ? "Current subject" : "Tenant subject"}</span>
        <strong>${escapeHtml(subject.displayName)}</strong>
        <small>${escapeHtml(subject.roleLabel)} · ${escapeHtml(subject.subjectId)}</small>
      </div>
      ${operationButton({ operation: "issue", subjectId: subject.subjectId, decision: subject.operations.issue })}
    </article>
  `).join("");

  document.querySelector("#certificate-rows").innerHTML = data.certificates.length ? data.certificates.map((certificate) => `
    <tr>
      <td><strong class="certificate-owner">${escapeHtml(certificate.subjectName)}</strong>${certificate.isCurrentCertificate ? '<small class="current-label">Current login certificate</small>' : ""}</td>
      <td><div class="certificate-id"><strong>${escapeHtml(certificate.serial)}</strong><small>${escapeHtml(certificate.certificateId)}</small></div></td>
      <td><span class="certificate-state ${escapeHtml(certificate.state)}">${escapeHtml(certificate.state)}</span></td>
      <td>${dateFormatter.format(new Date(certificate.expiresOn))}</td>
      <td>${operationButton({ operation: "renew", subjectId: certificate.subjectId, certificateId: certificate.certificateId, decision: certificate.operations.renew })}</td>
      <td>${operationButton({ operation: "revoke", subjectId: certificate.subjectId, certificateId: certificate.certificateId, decision: certificate.operations.revoke })}</td>
    </tr>
  `).join("") : '<tr class="empty-row"><td colspan="6">No certificates are visible in this tenant scope.</td></tr>';
}

function formatAge(seconds) {
  if (seconds < 60) return `${Math.floor(seconds)} seconds`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)} minutes`;
  return `${(seconds / 3_600).toFixed(1)} hours`;
}

function renderTrustDashboard(data) {
  const subjects = data.trustSubjects;
  const summary = data.trustSummary;
  document.querySelector("#trust-subject-total").textContent = summary.subjectCount;
  document.querySelector("#trust-fresh-total").textContent = summary.freshCount;
  document.querySelector("#trust-decision-total").textContent = summary.decisionCount;
  document.querySelector("#trust-bundle-version").textContent = summary.bundleVersion === null ? "—" : `v${summary.bundleVersion}`;

  if (!subjects.some(({ subjectId }) => subjectId === state.trustSubjectId)) {
    state.trustSubjectId = summary.currentSubjectId ?? subjects[0]?.subjectId ?? null;
  }
  const subject = subjects.find(({ subjectId }) => subjectId === state.trustSubjectId) ?? subjects[0];
  const picker = document.querySelector("#trust-subject-picker");
  picker.innerHTML = subjects.map((candidate) => `
    <button class="trust-subject-button ${candidate.subjectId === subject?.subjectId ? "active" : ""}" type="button" data-trust-subject="${escapeHtml(candidate.subjectId)}">
      <span>${escapeHtml(candidate.initials)}</span>
      <span><strong>${escapeHtml(candidate.displayName)}</strong><small>${escapeHtml(candidate.roleLabel)}</small></span>
      <b class="${escapeHtml(candidate.freshness.state)}">${escapeHtml(candidate.freshness.state)}</b>
    </button>
  `).join("");
  if (!subject) return;

  const score = subject.current.lastKnownScore;
  const freshness = subject.freshness;
  document.querySelector("#trust-subject-name").textContent = subject.displayName;
  document.querySelector("#trust-score").textContent = score.toFixed(2).replace(/\.00$/u, "");
  document.querySelector("#trust-score-ring").style.setProperty("--trust-score", score);
  const band = document.querySelector("#trust-band");
  band.className = `trust-band ${subject.current.band}`;
  band.textContent = `${subject.current.band} trust`;
  document.querySelector("#trust-score-status").textContent = freshness.usableForPolicy
    ? "Usable for policy"
    : "Withheld from policy";
  document.querySelector("#trust-age").textContent = `Observed ${formatAge(freshness.ageSeconds)} ago · stale after ${formatAge(freshness.staleAfterSeconds)}`;
  const freshnessBadge = document.querySelector("#trust-freshness");
  freshnessBadge.className = `status-pill ${freshness.state === "fresh" ? "success" : "danger"}`;
  freshnessBadge.innerHTML = `<span></span> ${escapeHtml(freshness.state)}`;
  document.querySelector("#trust-model-version").textContent = `v${subject.current.modelVersion}`;
  document.querySelector("#trust-configuration-version").textContent = `v${subject.current.configurationVersion}`;
  document.querySelector("#trust-update-version").textContent = `v${subject.current.updateVersion}`;

  document.querySelector("#trust-components").innerHTML = subject.components.map((component) => `
    <div class="trust-component" title="${escapeHtml(component.meaning)}">
      <div class="trust-component-copy"><strong>${escapeHtml(component.label)}</strong><span>${component.value.toFixed(0)} · ${(component.weight * 100).toFixed(0)}% weight</span></div>
      <div class="trust-component-track"><span style="width:${component.value}%"></span></div>
      <b>${component.weightedContribution.toFixed(2)}</b>
    </div>
  `).join("");

  document.querySelector("#trust-policy-version").textContent = subject.policy.policyVersionId;
  document.querySelector("#trust-policy-bundle").textContent = `v${subject.policy.bundleVersion}`;
  document.querySelector("#trust-policy-profile").textContent = subject.policy.profile;
  document.querySelector("#trust-calibration").textContent = subject.policy.calibrationStatus.replaceAll("-", " ");

  document.querySelector("#trust-decision-rows").innerHTML = subject.decisions.map((decision) => `
    <tr>
      <td>${dateFormatter.format(new Date(decision.evaluatedAt))}<small class="decision-time">${timeFormatter.format(new Date(decision.evaluatedAt))}</small></td>
      <td><strong class="decision-action">${escapeHtml(formatAction(decision.action))}</strong></td>
      <td><span class="decision-outcome ${decision.outcome.toLowerCase()}">${escapeHtml(decision.outcome)}</span></td>
      <td><code class="decision-reason">${escapeHtml(decision.reasonCodes.join(", "))}</code></td>
      <td>${decision.trustScore.toFixed(2).replace(/\.00$/u, "")} <small class="decision-band">${escapeHtml(decision.trustBand)}</small></td>
      <td><span class="decision-policy">bundle v${decision.bundleVersion}</span></td>
    </tr>
  `).join("");

  document.querySelector("#trust-transition-list").innerHTML = subject.transitions.map((transition) => {
    const delta = transition.previousScore === null ? null : transition.newScore - transition.previousScore;
    const deltaLabel = delta === null ? "Initial state" : `${delta >= 0 ? "+" : ""}${delta.toFixed(2)}`;
    return `
      <div class="transition-row">
        <span class="transition-dot ${escapeHtml(transition.newBand)}"></span>
        <div><strong>${escapeHtml(transition.trigger)}</strong><small>${dateFormatter.format(new Date(transition.observedAt))} · ${timeFormatter.format(new Date(transition.observedAt))}</small></div>
        <div class="transition-score"><strong>${transition.newScore.toFixed(2).replace(/\.00$/u, "")}</strong><span class="${delta !== null && delta < 0 ? "negative" : ""}">${deltaLabel}</span></div>
        <code>${escapeHtml(transition.reasonCode)}</code>
      </div>
    `;
  }).join("");
}

function renderPersonaPicker(data) {
  const picker = document.querySelector("#persona-picker");
  picker.innerHTML = data.personas.map((persona) => `<option value="${persona.key}">${persona.displayName} · ${persona.tenant.name}</option>`).join("");
  picker.value = state.personaKey;
}

function renderRecords(records, query = "") {
  const normalizedQuery = query.trim().toLowerCase();
  const visible = records.filter((record) => [record.name, record.category, record.classification, record.recordId]
    .some((value) => value.toLowerCase().includes(normalizedQuery)));
  document.querySelector("#record-count").textContent = `${records.length} permitted ${records.length === 1 ? "record" : "records"}`;
  document.querySelector("#record-rows").innerHTML = visible.length ? visible.map((record) => `
    <tr>
      <td><div class="record-name"><span class="record-icon">${icons.document}</span><span><strong>${escapeHtml(record.name)}</strong><small>${escapeHtml(record.recordId)}</small></span></div></td>
      <td>${escapeHtml(record.category)}</td>
      <td><span class="classification">${escapeHtml(record.classification)}</span></td>
      <td>${dateFormatter.format(new Date(record.updatedAt))}</td>
      <td><span class="scope-check">Verified</span></td>
    </tr>
  `).join("") : '<tr class="empty-row"><td colspan="5">No permitted records match this search.</td></tr>';
}

function scenarioIcon(id) {
  if (id === "revoked-certificate") return icons.lock;
  if (id.includes("record") || id.includes("header")) return icons.document;
  return icons.flask;
}

function renderScenarios(scenarios) {
  document.querySelector("#scenario-list").innerHTML = scenarios.map((scenario) => `
    <button class="scenario-card" type="button" data-run-scenario="${scenario.id}">
      <span class="scenario-icon">${scenarioIcon(scenario.id)}</span>
      <div><span>${escapeHtml(scenario.eyebrow)}</span><strong>${escapeHtml(scenario.title)}</strong><small>${escapeHtml(scenario.description)}</small></div>
      ${icons.arrow}
    </button>
  `).join("");
}

function formatAction(action) {
  return action.replace(":", " · ").replaceAll("-", " ");
}

function renderActivity() {
  const container = document.querySelector("#overview-activity");
  if (!state.auditEvents.length) {
    container.innerHTML = `<div class="activity-empty">${icons.flask}<span>Run a boundary scenario to populate the correlated review trail.</span></div>`;
    return;
  }
  container.innerHTML = state.auditEvents.slice(0, 4).map((event) => `
    <div class="activity-item">
      <span class="activity-icon ${event.outcome}">${event.outcome === "allow" ? icons.check : icons.close}</span>
      <span><strong>${escapeHtml(formatAction(event.action))}</strong><small>${escapeHtml(event.tenant)} · ${timeFormatter.format(new Date(event.occurredAt))}</small></span>
      <span class="activity-code">HTTP ${event.statusCode}</span>
    </div>
  `).join("");
}

function renderAudit() {
  const operations = state.data.auditOperations;
  const { ledger, causal, actions } = operations.summary;
  const total = state.auditEvents.length;
  document.querySelector("#audit-count").textContent = actions.critical;
  document.querySelector("#audit-total").textContent = total;
  document.querySelector("#audit-committed").textContent = ledger.committed;
  document.querySelector("#audit-pending").textContent = ledger.pending;
  document.querySelector("#audit-failed").textContent = ledger.failed;
  document.querySelector("#audit-verified").textContent = causal.verified;
  document.querySelector("#audit-scope").textContent = operations.scope.mode === "tenant"
    ? `${operations.scope.tenantName} · tenant scope`
    : `${operations.scope.tenantName} · self scope`;

  document.querySelector("#ledger-delivery-list").innerHTML = operations.ledgerDeliveries.map((delivery) => {
    const detail = delivery.deliveryStatus === "committed"
      ? `Block ${delivery.blockNumber} · ${delivery.transactionReference}`
      : delivery.deliveryStatus === "failed"
        ? `${delivery.failureCode} · retry ${timeFormatter.format(new Date(delivery.nextAttemptAt))}`
        : `Queued · next check ${timeFormatter.format(new Date(delivery.nextAttemptAt))}`;
    return `<div class="operation-row">
      <span class="operation-state ${escapeHtml(delivery.deliveryStatus)}">${delivery.deliveryStatus === "committed" ? icons.check : delivery.deliveryStatus === "failed" ? icons.close : icons.document}</span>
      <div class="operation-copy"><span>${escapeHtml(delivery.recordReference)} · ${escapeHtml(delivery.recordType)}</span><strong>${escapeHtml(delivery.eventType)}</strong><small>${escapeHtml(detail)}</small></div>
      <span class="state-pill ${escapeHtml(delivery.deliveryStatus)}">${escapeHtml(delivery.deliveryStatus)}</span>
    </div>`;
  }).join("");

  document.querySelector("#causal-verification-list").innerHTML = operations.causalChecks.map((check) => `
    <div class="operation-row">
      <span class="operation-state ${escapeHtml(check.result)}">${check.result === "verified" ? icons.check : check.result === "failed" ? icons.close : icons.document}</span>
      <div class="operation-copy"><span>${escapeHtml(check.correlationReference)} · ${check.eventCount} events</span><strong>${escapeHtml(check.reasonCode)}</strong><small>${escapeHtml(check.verifiedLinks.join(" → "))}</small></div>
      <span class="state-pill ${escapeHtml(check.result)}">${escapeHtml(check.result)}</span>
    </div>
  `).join("");

  const actionHealth = document.querySelector("#action-health");
  actionHealth.className = `health-pill ${escapeHtml(operations.summary.health)}`;
  actionHealth.textContent = `${operations.summary.health} · ${actions.critical} critical`;
  document.querySelector("#security-action-list").innerHTML = operations.securityActions.map((action) => {
    const retry = action.nextAttemptAt ? `Retry ${timeFormatter.format(new Date(action.nextAttemptAt))}` : "No retry required";
    return `<div class="action-operation-row">
      <span class="severity-marker ${escapeHtml(action.severity)}"></span>
      <div class="operation-copy"><span>${escapeHtml(action.actionReference)} · ${escapeHtml(action.authority)}</span><strong>${escapeHtml(formatAction(action.actionType))}</strong><small>${escapeHtml(action.issueCode)} · ${escapeHtml(retry)}</small></div>
      <div class="action-state"><span class="state-pill ${escapeHtml(action.status)}">${escapeHtml(action.status)}</span><small>Audit ${escapeHtml(action.auditDeliveryStatus)}</small></div>
      <div class="attempt-count"><strong>${action.attemptCount}</strong><span>attempts</span></div>
    </div>`;
  }).join("");

  const container = document.querySelector("#audit-list");
  if (!total) {
    container.innerHTML = `<div class="audit-empty">${icons.document}<div><strong>No session events yet</strong><span>Run an access-lab scenario to add a sanitized request outcome.</span></div></div>`;
    return;
  }
  container.innerHTML = state.auditEvents.map((event) => `
    <div class="audit-row">
      <span class="audit-outcome ${event.outcome}">${event.outcome === "allow" ? icons.check : icons.close}</span>
      <div class="audit-cell"><span>Actor</span><strong>${escapeHtml(event.actor)}</strong></div>
      <div class="audit-cell"><span>Action</span><strong>${escapeHtml(formatAction(event.action))}</strong></div>
      <div class="audit-cell"><span>Time</span><strong>${timeFormatter.format(new Date(event.occurredAt))}</strong></div>
      <div class="audit-cell"><span>Result</span><strong class="audit-reason">${escapeHtml(event.reasonCode)}</strong></div>
    </div>
  `).join("");
}

function renderResult(result) {
  const response = {
    status: result.statusCode,
    decision: result.outcome.toUpperCase(),
    reason: result.reasonCode,
    ...(result.operationId ? { operationId: result.operationId } : {}),
  };
  document.querySelector("#result-panel").innerHTML = `
    <div class="result-content">
      <div class="result-hero ${result.outcome}">
        <div><p class="eyebrow">${result.outcome === "allow" ? "Request accepted" : "Request stopped"}</p><h3>${escapeHtml(result.headline)}</h3><p>${escapeHtml(result.summary)}</p></div>
        <span class="http-code">HTTP ${result.statusCode}</span>
      </div>
      <div class="trace">
        <p class="trace-title">Decision trace</p>
        ${result.stages.map((stage) => `
          <div class="trace-step">
            <span class="trace-marker ${stage.state}">${stage.state === "pass" ? icons.check : stage.state === "fail" ? icons.close : icons.lock}</span>
            <span><strong>${escapeHtml(stage.label)}</strong><small>${escapeHtml(stage.detail)}</small></span>
            <span class="trace-state ${stage.state}">${stage.state}</span>
          </div>
        `).join("")}
      </div>
      <div class="response-box"><header><span>Sanitized response</span><span>${escapeHtml(result.event.correlationId)}</span></header><pre>${escapeHtml(JSON.stringify(response, null, 2))}</pre></div>
    </div>
  `;
}

async function loadState() {
  const data = await fetchJson(`/api/demo/state?persona=${encodeURIComponent(state.personaKey)}`);
  state.data = data;
  state.auditEvents = data.auditEvents;
  renderMetrics(data.project, data.certificateSummary);
  renderPersonaPicker(data);
  renderPersona(data);
  renderCertificateDashboard(data);
  renderTrustDashboard(data);
  renderRecords(data.records, document.querySelector("#record-search").value);
  renderScenarios(data.scenarios);
  renderActivity();
  renderAudit();
}

async function runCertificateOperation(button) {
  const operation = button.dataset.certificateOperation;
  const subjectId = button.dataset.subjectId;
  const certificateId = button.dataset.certificateId || null;
  button.disabled = true;
  button.classList.add("working");
  try {
    const result = await fetchJson("/api/demo/certificates/operations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ personaKey: state.personaKey, operation, subjectId, certificateId }),
    });
    await loadState();
    const resultPanel = document.querySelector("#certificate-operation-result");
    resultPanel.classList.add("operation-success");
    resultPanel.innerHTML = `${icons.check}<div><strong>${escapeHtml(result.headline)}</strong><span>${escapeHtml(result.summary)} The server recorded ${escapeHtml(result.reasonCode)}.</span></div>`;
    showToast(result.headline);
  } catch (error) {
    const resultPanel = document.querySelector("#certificate-operation-result");
    resultPanel.classList.remove("operation-success");
    resultPanel.innerHTML = `${icons.close}<div><strong>Certificate operation denied</strong><span>${escapeHtml(operationReason(error.reasonCode ?? "REQUEST_FAILED"))}. The server made no inventory change.</span></div>`;
    showToast(`Operation denied · ${error.reasonCode ?? "REQUEST_FAILED"}`);
  } finally {
    button.classList.remove("working");
    if (document.body.contains(button)) button.disabled = false;
  }
}

async function runScenario(scenarioId) {
  setView("lab");
  document.querySelectorAll(".scenario-card").forEach((button) => button.classList.toggle("running", button.dataset.runScenario === scenarioId));
  const panel = document.querySelector("#result-panel");
  panel.innerHTML = '<div class="result-empty"><div class="empty-icon">' + icons.flask + '</div><h3>Evaluating request</h3><p>Resolving certificate identity, tenant state, role and resource scope.</p></div>';
  try {
    const result = await fetchJson("/api/demo/scenarios", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ personaKey: state.personaKey, scenarioId }),
    });
    state.lastResult = result;
    state.auditEvents.unshift(result.event);
    renderResult(result);
    renderActivity();
    renderAudit();
    showToast(`${result.headline} · HTTP ${result.statusCode}`);
  } catch {
    panel.innerHTML = `<div class="result-empty"><div class="empty-icon">${icons.close}</div><h3>Scenario unavailable</h3><p>The local review server did not return a result. Restart it with npm run demo:review.</p></div>`;
  } finally {
    document.querySelectorAll(".scenario-card").forEach((button) => button.classList.remove("running"));
  }
}

document.addEventListener("click", (event) => {
  const navButton = event.target.closest("[data-view]");
  if (navButton) setView(navButton.dataset.view);

  const viewLink = event.target.closest("[data-view-link]");
  if (viewLink) setView(viewLink.dataset.viewLink);

  if (event.target.closest("[data-open-lab]")) setView("lab");

  const scenarioButton = event.target.closest("[data-run-scenario]");
  if (scenarioButton) runScenario(scenarioButton.dataset.runScenario);

  const certificateButton = event.target.closest("[data-certificate-operation]");
  if (certificateButton && !certificateButton.disabled) runCertificateOperation(certificateButton);

  const trustSubjectButton = event.target.closest("[data-trust-subject]");
  if (trustSubjectButton) {
    state.trustSubjectId = trustSubjectButton.dataset.trustSubject;
    renderTrustDashboard(state.data);
  }
});

document.querySelector("#persona-picker").addEventListener("change", async (event) => {
  state.personaKey = event.target.value;
  state.trustSubjectId = null;
  await loadState();
  showToast(`Switched to ${state.data.persona.displayName} in ${state.data.persona.tenant.name}`);
});

document.querySelector("#record-search").addEventListener("input", (event) => renderRecords(state.data.records, event.target.value));
document.querySelector("#export-button").addEventListener("click", () => runScenario("sensitive-export"));

const requestedView = window.location.hash.slice(1);
if (pageTitles[requestedView]) setView(requestedView);

loadState().catch(() => {
  document.querySelector(".content").innerHTML = '<section class="view active"><div class="result-empty"><h3>Review console unavailable</h3><p>Restart the local server with <code>npm run demo:review</code>.</p></div></section>';
});
