import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAuditOperationsDashboard } from "./audit-operations-dashboard.mjs";
import { CertificateDashboardError, createCertificateDashboard } from "./certificate-dashboard.mjs";
import { getReviewState, runReviewScenario } from "./demo-domain.mjs";
import { createTrustDashboard } from "./trust-dashboard.mjs";

const host = process.env.REVIEW_DEMO_HOST ?? "127.0.0.1";
const port = Number(process.env.REVIEW_DEMO_PORT ?? 4173);
const appDirectory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.join(appDirectory, "public");
const auditEvents = [];
const auditOperationsDashboard = createAuditOperationsDashboard();
const certificateDashboard = createCertificateDashboard();
const trustDashboard = createTrustDashboard();
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(payload));
}

async function readJson(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 16_384) throw new RangeError("Request body is too large.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

async function serveStatic(requestUrl, response) {
  const requestedPath = requestUrl.pathname === "/" ? "/index.html" : requestUrl.pathname;
  const resolvedPath = path.resolve(publicDirectory, `.${requestedPath}`);
  if (!resolvedPath.startsWith(`${publicDirectory}${path.sep}`)) {
    sendJson(response, 404, { error: "NOT_FOUND" });
    return;
  }

  try {
    const file = await stat(resolvedPath);
    if (!file.isFile()) throw new Error("Not a file.");
    response.writeHead(200, {
      "content-type": contentTypes.get(path.extname(resolvedPath)) ?? "application/octet-stream",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    });
    createReadStream(resolvedPath).pipe(response);
  } catch {
    sendJson(response, 404, { error: "NOT_FOUND" });
  }
}

const server = createServer(async (request, response) => {
  const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? host}`);

  try {
    if (request.method === "GET" && requestUrl.pathname === "/api/health") {
      sendJson(response, 200, { status: "ok", mode: "review-demo" });
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/api/demo/state") {
      const personaKey = requestUrl.searchParams.get("persona") ?? undefined;
      const state = getReviewState(personaKey);
      const dashboard = certificateDashboard.getState(personaKey);
      const trust = trustDashboard.getState(personaKey);
      const auditOperations = auditOperationsDashboard.getState(personaKey);
      sendJson(response, 200, {
        ...state,
        ...dashboard,
        ...trust,
        ...auditOperations,
        certificate: dashboard.currentCertificate ?? state.certificate,
        auditEvents: auditEvents.slice(0, 12),
      });
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/demo/scenarios") {
      const body = await readJson(request);
      const result = runReviewScenario({ personaKey: body.personaKey, scenarioId: body.scenarioId });
      auditEvents.unshift(result.event);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/demo/certificates/operations") {
      const body = await readJson(request);
      const result = certificateDashboard.execute({
        personaKey: body.personaKey,
        operation: body.operation,
        subjectId: body.subjectId,
        certificateId: body.certificateId,
      });
      auditEvents.unshift(result.event);
      sendJson(response, 200, result);
      return;
    }
    if (requestUrl.pathname.startsWith("/api/")) {
      sendJson(response, 404, { error: "NOT_FOUND" });
      return;
    }
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "METHOD_NOT_ALLOWED" });
      return;
    }
    await serveStatic(requestUrl, response);
  } catch (error) {
    if (error instanceof CertificateDashboardError) {
      sendJson(response, error.statusCode, { error: error.reasonCode });
      return;
    }
    const invalidRequest = error instanceof RangeError || error instanceof SyntaxError;
    sendJson(response, invalidRequest ? 400 : 500, {
      error: invalidRequest ? "INVALID_REQUEST" : "INTERNAL_FAILURE",
    });
  }
});

server.listen(port, host, () => {
  console.log(`Tenant Trust review console: http://${host}:${port}`);
  console.log("Press Ctrl+C to stop.");
});
