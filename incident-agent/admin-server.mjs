import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { atomicWriteJson, ensureDirectory, readJson, readRequestBody } from "./lib/runtime.mjs";

const stateDirectory = process.env.STATE_DIRECTORY ?? "/var/lib/fasrv-incident-agent";
const eventDirectory = path.join(stateDirectory, "events");
const queueDirectory = path.join(stateDirectory, "queue");
const processingDirectory = path.join(stateDirectory, "processing");
const quarantineDirectory = path.join(stateDirectory, "quarantine");
const pauseFile = path.join(stateDirectory, "PAUSED");
const staticDirectory = process.env.STATIC_DIRECTORY ?? path.join(import.meta.dirname, "admin");
const port = Number(process.env.PORT ?? 8153);
const controlToken = crypto.randomBytes(32).toString("base64url");

ensureDirectory(quarantineDirectory, 0o770);

const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/admin.css", ["admin.css", "text/css; charset=utf-8"]],
  ["/admin.js", ["admin.js", "text/javascript; charset=utf-8"]]
]);

function securityHeaders(contentType) {
  return {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "content-type": contentType,
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY"
  };
}

function respond(response, status, payload) {
  response.writeHead(status, securityHeaders("application/json; charset=utf-8"));
  response.end(`${JSON.stringify(payload)}\n`);
}

function readPauseState() {
  if (!fs.existsSync(pauseFile)) return null;
  return readJson(pauseFile, { pausedAt: null, reasonCode: "security_pause", source: "security" });
}

function readEvents() {
  if (!fs.existsSync(eventDirectory)) return [];
  return fs.readdirSync(eventDirectory)
    .filter((name) => /^\d{13}-\d{6}\.json$/u.test(name))
    .sort()
    .slice(-250)
    .flatMap((name) => {
      const event = readJson(path.join(eventDirectory, name));
      return event ? [event] : [];
    });
}

function requestIsLocal(request) {
  const host = request.headers.host;
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
}

function controlIsAuthorized(request) {
  const origin = request.headers.origin;
  const validOrigin = origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}`;
  const supplied = String(request.headers["x-control-token"] ?? "");
  const expected = Buffer.from(controlToken);
  const actual = Buffer.from(supplied);
  return validOrigin && actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function resumeManualWork(pause) {
  if (pause?.source !== "manual_admin" || !fs.existsSync(processingDirectory)) return 0;
  let resumed = 0;
  for (const name of fs.readdirSync(processingDirectory).filter((file) => /^[0-9a-f-]{36}\.json$/u.test(file))) {
    const source = path.join(processingDirectory, name);
    const target = path.join(queueDirectory, name);
    if (!fs.existsSync(target)) {
      fs.renameSync(source, target);
      resumed += 1;
    }
  }
  return resumed;
}

function quarantineUnsafeWork(pause) {
  if (pause?.source === "manual_admin" || !fs.existsSync(processingDirectory)) return 0;
  let quarantined = 0;
  const prefix = `${Date.now()}-`;
  for (const name of fs.readdirSync(processingDirectory).filter((file) => /^[0-9a-f-]{36}(?:\.state)?\.json$/u.test(file))) {
    fs.renameSync(path.join(processingDirectory, name), path.join(quarantineDirectory, `${prefix}${name}`));
    quarantined += 1;
  }
  return quarantined;
}

const server = http.createServer(async (request, response) => {
  try {
    if (!requestIsLocal(request)) return respond(response, 403, { error: "local_only" });
    const url = new URL(request.url, `http://127.0.0.1:${port}`);
    if (request.method === "GET" && STATIC_FILES.has(url.pathname)) {
      const [filename, contentType] = STATIC_FILES.get(url.pathname);
      response.writeHead(200, securityHeaders(contentType));
      return response.end(fs.readFileSync(path.join(staticDirectory, filename)));
    }
    if (request.method === "GET" && url.pathname === "/api/snapshot") {
      const pause = readPauseState();
      return respond(response, 200, { paused: Boolean(pause), pause, events: readEvents(), controlToken, serverTime: new Date().toISOString() });
    }
    if (request.method === "POST" && url.pathname === "/api/control") {
      if (!controlIsAuthorized(request)) return respond(response, 403, { error: "control_denied" });
      if (request.headers["content-type"]?.split(";", 1)[0] !== "application/json") return respond(response, 415, { error: "json_required" });
      const payload = JSON.parse(await readRequestBody(request, 256));
      if (payload.action === "block") {
        if (!fs.existsSync(pauseFile)) atomicWriteJson(pauseFile, { pausedAt: new Date().toISOString(), reasonCode: "manual_block", source: "manual_admin" }, 0o640);
      } else if (payload.action === "unblock") {
        const pause = readPauseState();
        resumeManualWork(pause);
        quarantineUnsafeWork(pause);
        fs.rmSync(pauseFile, { force: true });
      } else return respond(response, 400, { error: "invalid_action" });
      return respond(response, 200, { paused: fs.existsSync(pauseFile) });
    }
    return respond(response, 404, { error: "not_found" });
  } catch {
    return respond(response, 400, { error: "invalid_request" });
  }
});

server.requestTimeout = 10000;
server.headersTimeout = 5000;
server.listen(port, "127.0.0.1", () => console.log(`incident admin listening on 127.0.0.1:${port}`));
