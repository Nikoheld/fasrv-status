import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { atomicWriteJson, ensureDirectory, isPaused, readRequestBody, tripCircuitBreaker } from "./lib/runtime.mjs";
import { detectPromptInjection, sha256, validateDescription, validateSeries } from "./lib/security.mjs";

const stateDirectory = process.env.STATE_DIRECTORY ?? "/var/lib/fasrv-incident-agent";
const queueDirectory = path.join(stateDirectory, "queue");
const port = Number(process.env.PORT ?? 8152);
const allowedOrigin = process.env.ALLOWED_ORIGIN ?? "https://status.fasrv.ch";
const proofDifficulty = Number(process.env.POW_DIFFICULTY ?? 4);
const apps = JSON.parse(fs.readFileSync(process.env.APP_CONFIG ?? "/etc/fasrv-incident-agent/apps.json", "utf8"));
const appBySlug = new Map(apps.map((app) => [app.slug, app]));
const challenges = new Map();
const submissions = new Map();

ensureDirectory(queueDirectory, 0o770);

function headers(origin = allowedOrigin) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "600",
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff"
  };
}

function respond(response, status, payload) {
  response.writeHead(status, headers());
  response.end(`${JSON.stringify(payload)}\n`);
}

function clientAddress(request) {
  return String(request.headers["x-real-ip"] ?? request.socket.remoteAddress ?? "unknown").slice(0, 80);
}

function cleanup() {
  const now = Date.now();
  for (const [key, value] of challenges) if (value.expiresAt < now) challenges.delete(key);
  for (const [key, values] of submissions) submissions.set(key, values.filter((time) => now - time < 3600000));
}

function createChallenge(address) {
  cleanup();
  const id = crypto.randomUUID();
  const nonce = crypto.randomBytes(24).toString("hex");
  challenges.set(id, { nonce, addressHash: sha256(address), expiresAt: Date.now() + 120000 });
  return { id, nonce, difficulty: proofDifficulty, expiresIn: 120 };
}

function consumeChallenge(address, proof) {
  if (!proof || typeof proof.id !== "string" || !Number.isSafeInteger(proof.counter) || proof.counter < 0) return false;
  const challenge = challenges.get(proof.id);
  challenges.delete(proof.id);
  if (!challenge || challenge.expiresAt < Date.now() || challenge.addressHash !== sha256(address)) return false;
  return sha256(`${challenge.nonce}:${proof.counter}`).startsWith("0".repeat(proofDifficulty));
}

function isRateLimited(address) {
  cleanup();
  const key = sha256(address);
  const recent = submissions.get(key) ?? [];
  if (recent.length >= 3) return true;
  recent.push(Date.now());
  submissions.set(key, recent);
  return false;
}

const server = http.createServer(async (request, response) => {
  try {
    const origin = request.headers.origin;
    if (origin && origin !== allowedOrigin) return respond(response, 403, { error: "origin_not_allowed" });
    if (request.method === "OPTIONS") return respond(response, 204, {});
    if (request.method === "GET" && request.url === "/healthz") return respond(response, 200, { status: isPaused(stateDirectory) ? "paused" : "ok" });
    if (request.method === "GET" && request.url === "/v1/challenge") {
      if (isPaused(stateDirectory)) return respond(response, 503, { error: "temporarily_unavailable" });
      return respond(response, 200, createChallenge(clientAddress(request)));
    }
    if (request.method !== "POST" || request.url !== "/v1/reports") return respond(response, 404, { error: "not_found" });
    if (isPaused(stateDirectory)) return respond(response, 503, { error: "temporarily_unavailable" });
    if (request.headers["content-type"]?.split(";", 1)[0] !== "application/json") return respond(response, 415, { error: "json_required" });

    const address = clientAddress(request);
    if (isRateLimited(address)) return respond(response, 429, { error: "rate_limited" });
    const payload = JSON.parse(await readRequestBody(request));
    if (payload.website) return respond(response, 202, { accepted: true });
    if (!consumeChallenge(address, payload.proof)) return respond(response, 400, { error: "invalid_challenge" });
    if (typeof payload.app !== "string" || !appBySlug.has(payload.app)) return respond(response, 400, { error: "invalid_application" });

    let description;
    let series;
    try {
      description = validateDescription(payload.description);
      series = validateSeries(payload.series);
      if (payload.app !== "jellyfin" && series) throw new Error("series_not_allowed");
    } catch (error) {
      if (error.message === "prompt_injection" || detectPromptInjection(payload.description) || detectPromptInjection(payload.series)) {
        tripCircuitBreaker(stateDirectory, error.code ?? "prompt_injection", "public_form");
        return respond(response, 400, { error: "request_rejected" });
      }
      return respond(response, 400, { error: "invalid_report" });
    }

    const id = crypto.randomUUID();
    atomicWriteJson(path.join(queueDirectory, `${id}.json`), {
      id,
      app: payload.app,
      description,
      series,
      createdAt: new Date().toISOString(),
      sourceHash: sha256(address)
    }, 0o640);
    return respond(response, 202, { accepted: true, reference: id });
  } catch {
    return respond(response, 400, { error: "invalid_request" });
  }
});

server.requestTimeout = 10000;
server.headersTimeout = 5000;
server.listen(port, "127.0.0.1", () => console.log(`report-api listening on 127.0.0.1:${port}`));
