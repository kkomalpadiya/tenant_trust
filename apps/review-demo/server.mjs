import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getReviewState, runReviewScenario } from "./demo-domain.mjs";

const host = process.env.REVIEW_DEMO_HOST ?? "127.0.0.1";
const port = Number(process.env.REVIEW_DEMO_PORT ?? 4173);
const appDirectory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.join(appDirectory, "public");
const auditEvents = [];
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
      const state = getReviewState(requestUrl.searchParams.get("persona") ?? undefined);
      sendJson(response, 200, { ...state, auditEvents: auditEvents.slice(0, 12) });
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/demo/scenarios") {
      const body = await readJson(request);
      const result = runReviewScenario({ personaKey: body.personaKey, scenarioId: body.scenarioId });
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
    sendJson(response, error instanceof RangeError || error instanceof SyntaxError ? 400 : 500, {
      error: error instanceof RangeError || error instanceof SyntaxError ? "INVALID_REQUEST" : "INTERNAL_FAILURE",
    });
  }
});

server.listen(port, host, () => {
  console.log(`Tenant Trust review console: http://${host}:${port}`);
  console.log("Press Ctrl+C to stop.");
});
