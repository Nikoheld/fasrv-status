import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { atomicWriteJson, ensureDirectory, isPaused, readJson, tripCircuitBreaker } from "./lib/runtime.mjs";
import { detectPromptInjection, SecretScanner, validateDescription, validateSeries } from "./lib/security.mjs";
import { allowedActionsFor, isSecurityInterruption, noActionReasonFor, outcomeComment, outcomeMarker } from "./lib/remediation.mjs";
import { originRestarted } from "./lib/origin-state.mjs";

const stateDirectory = process.env.STATE_DIRECTORY ?? "/var/lib/fasrv-incident-agent";
const queueDirectory = path.join(stateDirectory, "queue");
const processingDirectory = path.join(stateDirectory, "processing");
const quarantineDirectory = path.join(stateDirectory, "quarantine");
const archiveDirectory = path.join(stateDirectory, "archive");
const modelDirectory = path.join(stateDirectory, "model-output");
const eventDirectory = path.join(stateDirectory, "events");
const appConfig = process.env.APP_CONFIG ?? "/etc/fasrv-incident-agent/apps.json";
const promptDirectory = process.env.PROMPT_DIRECTORY ?? path.join(import.meta.dirname, "prompts");
const repository = process.env.GITHUB_REPOSITORY ?? "Nikoheld/fasrv-status";
const trustedGithubUser = process.env.TRUSTED_GITHUB_USER ?? "Nikoheld";
const githubToken = fs.readFileSync(process.env.GITHUB_TOKEN_FILE ?? "/etc/fasrv-incident-agent/github-token", "utf8").trim();
const grokBinary = process.env.GROK_BINARY ?? "/home/codexweb/.grok/bin/grok";
const grokReasoningEffort = process.env.GROK_REASONING_EFFORT ?? "low";
const jellyfinRemediationHelper = process.env.JELLYFIN_REMEDIATION_HELPER ?? "/usr/local/sbin/fasrv-jellyfin-remediate";
const pollSeconds = Number(process.env.POLL_SECONDS ?? 30);
const apps = JSON.parse(fs.readFileSync(appConfig, "utf8"));
const appBySlug = new Map(apps.map((app) => [app.slug, app]));
const scanner = SecretScanner.fromPaths((process.env.SECRET_PATHS ?? "/srv/codex-web/shared-credentials:/home/codexweb/.grok/auth.json:/etc/fasrv-incident-agent/github-token").split(":"));
const controllerStateFile = path.join(stateDirectory, "controller.json");
const freshControllerState = !fs.existsSync(controllerStateFile);
let controllerState = readJson(controllerStateFile, { startedAt: new Date().toISOString(), seenIssues: [] });
controllerState.localHealth ??= {};

if (!new Set(["low", "medium", "high"]).has(grokReasoningEffort)) throw new Error("invalid_grok_reasoning_effort");

ensureDirectory(queueDirectory, 0o770);
ensureDirectory(eventDirectory, 0o770);
ensureDirectory(processingDirectory, 0o770);
ensureDirectory(quarantineDirectory, 0o770);
for (const directory of [archiveDirectory, modelDirectory]) ensureDirectory(directory);
let eventSequence = 0;

const SUMMARY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["category", "severity", "suspicious", "internalSummary", "classificationBasis"],
  properties: {
    category: { type: "string", enum: ["availability", "login", "playback", "performance", "images", "anime_download", "content", "other"] },
    severity: { type: "string", enum: ["low", "medium", "high"] },
    suspicious: { type: "boolean" },
    internalSummary: { type: "string", minLength: 1, maxLength: 160 },
    classificationBasis: { type: "string", minLength: 1, maxLength: 220 }
  }
};

const FIX_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["action", "problemCode", "fixCode", "decisionSummary"],
  properties: {
    action: { type: "string", enum: ["no_action", "restart_origin", "reload_proxy", "refresh_jellyfin_images", "requeue_hianime"] },
    problemCode: { type: "string", enum: ["unavailable", "slow", "proxy", "origin", "image_metadata", "anime_download", "unknown"] },
    fixCode: { type: "string", enum: ["recovered", "restarted", "proxy_reloaded", "image_refresh_started", "anime_requeued", "not_executed", "no_change"] },
    decisionSummary: { type: "string", minLength: 1, maxLength: 220 }
  }
};

const CATEGORY_LABELS = {
  availability: "Erreichbarkeit",
  login: "Anmeldung",
  playback: "Wiedergabe",
  performance: "Geschwindigkeit",
  images: "Bilder und Metadaten",
  anime_download: "Anime-Download",
  content: "Inhalt",
  other: "Allgemeine Störung"
};

function log(event, fields = {}) {
  console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields }));
}

function stopForSecurity(reason, source) {
  tripCircuitBreaker(stateDirectory, reason, source);
  log("circuit_breaker_tripped", { reason, source });
}

function recordAgentEvent(agent, incidentId, stage, fields = {}) {
  const event = {
    time: new Date().toISOString(),
    agent,
    incidentId,
    stage,
    ...fields
  };
  const serialized = JSON.stringify(event);
  if (scanner.scan(serialized)) {
    stopForSecurity("event_secret_gate", "event_log");
    throw new Error("security_gate");
  }
  eventSequence = (eventSequence + 1) % 1000000;
  const filename = `${Date.now()}-${String(eventSequence).padStart(6, "0")}.json`;
  atomicWriteJson(path.join(eventDirectory, filename), event, 0o640);
  const files = fs.readdirSync(eventDirectory).filter((name) => name.endsWith(".json")).sort();
  for (const stale of files.slice(0, Math.max(0, files.length - 500))) fs.unlinkSync(path.join(eventDirectory, stale));
}

async function github(pathname, options = {}) {
  const response = await fetch(`https://api.github.com/repos/${repository}${pathname}`, {
    ...options,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${githubToken}`,
      "x-github-api-version": "2022-11-28",
      "user-agent": "fasrv-incident-agent/1.0",
      ...(options.headers ?? {})
    },
    signal: AbortSignal.timeout(15000)
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`github_${response.status}`);
  return text ? JSON.parse(text) : null;
}

async function githubWrite(pathname, method, payload) {
  const serialized = JSON.stringify(payload);
  const secret = scanner.scan(serialized);
  if (secret) {
    stopForSecurity(secret, "github_output_gate");
    throw new Error("security_gate");
  }
  if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
  return github(pathname, { method, body: serialized, headers: { "content-type": "application/json" } });
}

function runGrok(kind, prompt, schema) {
  return new Promise((resolve, reject) => {
    if (isPaused(stateDirectory)) return reject(new Error("pipeline_paused"));
    const systemPrompt = fs.readFileSync(path.join(promptDirectory, `${kind}.txt`), "utf8");
    const args = [
      "-p", prompt,
      "--system-prompt-override", systemPrompt,
      "--output-format", "json",
      "--json-schema", JSON.stringify(schema),
      "--no-memory",
      "--no-subagents",
      "--disable-web-search",
      "--reasoning-effort", grokReasoningEffort,
      "--max-turns", "1",
      "--tools", ""
    ];
    const child = spawn(grokBinary, args, {
      cwd: "/srv/fasrv-incident-agent",
      env: { HOME: "/home/codexweb", PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let pausedDuringRun = false;
    const timer = setTimeout(() => child.kill("SIGKILL"), 180000);
    const pauseTimer = setInterval(() => {
      if (isPaused(stateDirectory)) {
        pausedDuringRun = true;
        child.kill("SIGKILL");
      }
    }, 500);
    child.stdout.on("data", (chunk) => { if (stdout.length < 1048576) stdout += chunk; });
    child.stderr.on("data", (chunk) => { if (stderr.length < 1048576) stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      clearInterval(pauseTimer);
      if (pausedDuringRun) return reject(new Error("pipeline_paused"));
      const completeOutput = `${stdout}\n${stderr}`;
      const secret = scanner.scan(completeOutput);
      if (secret) {
        stopForSecurity(secret, `${kind}_secret_gate`);
        return reject(new Error("security_gate"));
      }
      if (code !== 0) return reject(new Error(`${kind}_failed_${code}`));
      try {
        const wrapper = JSON.parse(stdout);
        if (!wrapper.structuredOutput) throw new Error("missing_structured_output");
        const injection = detectPromptInjection(JSON.stringify(wrapper.structuredOutput));
        if (injection) {
          return reject(new Error("prompt_injection"));
        }
        resolve({ result: wrapper.structuredOutput, completeOutput });
      } catch {
        reject(new Error(`${kind}_invalid_json`));
      }
    });
  });
}

async function summarizeReport(report) {
  const description = validateDescription(report.description);
  const series = validateSeries(report.series);
  const untrustedInput = `${description}\n${series}`;
  const secret = scanner.scan(untrustedInput);
  if (secret) {
    throw new Error("report_contains_secret");
  }
  const injection = detectPromptInjection(untrustedInput);
  if (injection) {
    throw new Error("prompt_injection");
  }
  const payload = JSON.stringify({ application: report.app, description, series: series || null });
  recordAgentEvent("intake", report.id, "validated", {
    app: report.app,
    checks: ["format", "secret_scan", "prompt_injection"]
  });
  recordAgentEvent("intake", report.id, "started", { app: report.app });
  try {
    const output = await runGrok("summarizer", `Classify this JSON data object:\n${payload}`, SUMMARY_SCHEMA);
    if (output.result.suspicious) {
      throw new Error("prompt_injection");
    }
    recordAgentEvent("intake", report.id, "completed", {
      app: report.app,
      category: output.result.category,
      severity: output.result.severity,
      summary: output.result.internalSummary,
      reasoningSummary: output.result.classificationBasis
    });
    return output;
  } catch (error) {
    recordAgentEvent("intake", report.id, "failed", { app: report.app, code: error.message });
    throw error;
  }
}

async function probe(app) {
  const started = Date.now();
  if (!app.url) return { healthy: true, status: null, latencyMs: 0, skipped: true };
  try {
    const response = await fetch(app.url, { redirect: "manual", signal: AbortSignal.timeout(10000) });
    return { healthy: app.expectedStatusCodes.includes(response.status), status: response.status, latencyMs: Date.now() - started };
  } catch {
    return { healthy: false, status: 0, latencyMs: Date.now() - started };
  }
}

function configuredOrigins(app) {
  const origins = [];
  if (app.container) origins.push({ kind: "container", name: app.container, primary: true });
  if (app.unit) origins.push({ kind: "unit", name: app.unit, primary: true });
  for (const name of app.watchContainers ?? []) origins.push({ kind: "container", name, primary: false });
  for (const name of app.watchUnits ?? []) origins.push({ kind: "unit", name, primary: false });
  return origins.filter((origin, index, all) => all.findIndex((candidate) => candidate.kind === origin.kind && candidate.name === origin.name) === index);
}

function originKey(origin) {
  return `${origin.kind}:${origin.name}`;
}

function readOriginStateMap(origins) {
  const unique = origins.filter((origin, index, all) => all.findIndex((candidate) => originKey(candidate) === originKey(origin)) === index);
  const states = new Map(unique.map((origin) => [originKey(origin), { running: false, restartCount: 0, generation: "" }]));
  const containers = unique.filter((origin) => origin.kind === "container").map((origin) => origin.name);
  if (containers.length) {
    const inspection = spawnSync("sudo", ["-n", "docker", "inspect", "-f", "{{.Name}}|{{.State.Running}}|{{.RestartCount}}|{{.State.StartedAt}}", ...containers], { encoding: "utf8", timeout: 30000 });
    if (inspection.status === 0) {
      for (const line of inspection.stdout.trim().split("\n")) {
        const [rawName, running, restartCount, generation] = line.split("|");
        states.set(`container:${rawName.replace(/^\//u, "")}`, { running: running === "true", restartCount: Number(restartCount) || 0, generation });
      }
    }
  }
  const units = unique.filter((origin) => origin.kind === "unit").map((origin) => origin.name);
  if (units.length) {
    const inspection = spawnSync("sudo", ["-n", "systemctl", "show", "--property=Id", "--property=ActiveState", "--property=NRestarts", "--property=ActiveEnterTimestampMonotonic", ...units], { encoding: "utf8", timeout: 30000 });
    if (inspection.status === 0) {
      for (const block of inspection.stdout.trim().split(/\n\n+/u)) {
        const values = Object.fromEntries(block.split("\n").map((line) => line.split(/=(.*)/su).slice(0, 2)));
        if (values.Id) states.set(`unit:${values.Id}`, { running: values.ActiveState === "active", restartCount: Number(values.NRestarts) || 0, generation: values.ActiveEnterTimestampMonotonic ?? "" });
      }
    }
  }
  return states;
}

function readOriginStates(app, stateMap = readOriginStateMap(configuredOrigins(app))) {
  return configuredOrigins(app).map((origin) => ({ ...origin, ...(stateMap.get(originKey(origin)) ?? { running: false, restartCount: 0, generation: "" }) }));
}

function localFacts(app, publicProbe) {
  const origins = readOriginStates(app);
  const facts = {
    publicHealthy: publicProbe.healthy,
    publicStatusClass: publicProbe.skipped ? "not_configured" : publicProbe.status ? `${Math.floor(publicProbe.status / 100)}xx` : "network_error",
    publicLatencyClass: publicProbe.skipped ? "not_checked" : publicProbe.latencyMs < 1000 ? "fast" : publicProbe.latencyMs < 3000 ? "moderate" : "slow",
    originConfigured: origins.length > 0,
    originRunning: origins.length ? origins.every((origin) => origin.running) : null,
    failedOrigins: origins.filter((origin) => !origin.running).map((origin) => `${origin.kind}:${origin.name}`),
    proxyConfigurationValid: spawnSync("sudo", ["-n", "nginx", "-t"], { stdio: "ignore" }).status === 0
  };
  return facts;
}

function executeAction(app, action, series, facts) {
  if (!app.allowedActions.includes(action)) throw new Error("action_not_allowed");
  if (action === "no_action") return { accepted: true, target: "none", latencyMs: 0 };
  const started = Date.now();
  let result;
  if (action === "restart_origin") {
    const origins = configuredOrigins(app);
    const failed = new Set(facts?.failedOrigins ?? []);
    const targets = origins.filter((origin) => failed.has(`${origin.kind}:${origin.name}`));
    const selected = targets.length ? targets : origins.filter((origin) => origin.primary);
    if (!selected.length) throw new Error("action_unavailable");
    for (const origin of selected) {
      result = origin.kind === "container"
        ? spawnSync("sudo", ["-n", "docker", "restart", origin.name], { stdio: "ignore", timeout: 120000 })
        : spawnSync("sudo", ["-n", "systemctl", "restart", origin.name], { stdio: "ignore", timeout: 120000 });
      if (result.status !== 0) throw new Error("action_failed");
    }
    return { accepted: true, target: "origin_components", restarted: selected.map((origin) => `${origin.kind}:${origin.name}`), latencyMs: Date.now() - started };
  }
  if (action === "reload_proxy") {
    if (spawnSync("sudo", ["-n", "nginx", "-t"], { stdio: "ignore" }).status !== 0) throw new Error("nginx_config_invalid");
    result = spawnSync("sudo", ["-n", "systemctl", "reload", "nginx"], { stdio: "ignore", timeout: 30000 });
  } else if (action === "refresh_jellyfin_images" || action === "requeue_hianime") {
    const helperAction = action === "refresh_jellyfin_images" ? "refresh-images" : "requeue-hianime";
    result = spawnSync("sudo", ["-n", jellyfinRemediationHelper, helperAction, series], { encoding: "utf8", timeout: 240000 });
    if (result.status !== 0) {
      const code = readJsonFromString(result.stdout)?.code;
      const allowedCodes = new Set(["hianime_match_not_found", "jellyfin_item_not_found", "jellyfin_refresh_timeout", "jellyfin_image_not_verified"]);
      throw new Error(allowedCodes.has(code) ? code : "helper_failed");
    }
    const helperResult = readJsonFromString(result.stdout);
    if (!helperResult?.ok || !helperResult.accepted) throw new Error("helper_failed");
    return { ...helperResult, latencyMs: Date.now() - started };
  } else throw new Error("action_unavailable");
  if (result.status !== 0) throw new Error("action_failed");
  return { accepted: true, target: actionTarget(app, action), latencyMs: Date.now() - started };
}

function readJsonFromString(value) {
  try { return JSON.parse(String(value ?? "")); } catch { return null; }
}

function actionTarget(app, action) {
  if (action === "restart_origin") return "origin_components";
  if (action === "reload_proxy") return "nginx_proxy";
  if (action === "refresh_jellyfin_images") return "jellyfin_library";
  if (action === "requeue_hianime") return "hianime_queue";
  return "none";
}

async function verifyRecovery(app, category, action, actionResult) {
  const checks = [];
  if (action === "requeue_hianime") {
    checks.push({ attempt: 1, healthy: Boolean(actionResult?.accepted), status: actionResult?.accepted ? 202 : 0, latencyMs: actionResult?.latencyMs ?? 0 });
    return { verified: Boolean(actionResult?.accepted), checks };
  }
  if (action === "refresh_jellyfin_images") {
    checks.push({
      kind: "image",
      healthy: Boolean(actionResult?.verified),
      primary: actionResult?.primary,
      backdrop: actionResult?.backdrop,
      displayBlurDisabled: Boolean(actionResult?.displayBlurDisabled),
      latencyMs: actionResult?.latencyMs ?? 0
    });
    if (!actionResult?.verified) return { verified: false, checks };
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
    if (attempt) await delay(5000);
    const result = await probe(app);
    const origins = readOriginStates(app);
    const originsHealthy = origins.every((origin) => origin.running);
    const healthy = result.healthy && originsHealthy && !(category === "performance" && !result.skipped && result.latencyMs >= 3000);
    checks.push({ attempt: attempt + 1, healthy, status: result.status, latencyMs: result.latencyMs, originsHealthy });
    if (!healthy) continue;
  }
  return { verified: checks.length === 3 && checks.every((check) => check.healthy), checks };
}

async function githubCommentOnce(issueNumber, incidentId, body) {
  const issue = await github(`/issues/${issueNumber}`);
  if (issue.user?.login !== trustedGithubUser) throw new Error("untrusted_issue_author");
  const marker = outcomeMarker(incidentId);
  const comments = await github(`/issues/${issueNumber}/comments?per_page=100`);
  if (comments.some((comment) => String(comment.body ?? "").includes(marker))) return false;
  await githubWrite(`/issues/${issueNumber}/comments`, "POST", { body });
  return true;
}

function publicFailureCode(code) {
  const allowed = new Set(["action_failed", "helper_failed", "hianime_match_not_found", "jellyfin_item_not_found", "jellyfin_refresh_timeout", "jellyfin_image_not_verified", "recovery_not_verified"]);
  return allowed.has(code) ? code : "helper_failed";
}

async function analyzeAndFix({ app, category, issueNumber, incidentId, source, series = "" }) {
  const issue = await github(`/issues/${issueNumber}`);
  if (issue.user?.login !== trustedGithubUser) {
    log("issue_ignored_untrusted_author", { issueNumber, author: issue.user?.login ?? "unknown" });
    return false;
  }
  const initialProbe = await probe(app);
  const facts = localFacts(app, initialProbe);
  const hasSeries = Boolean(series);
  const allowedActions = allowedActionsFor(app, category, hasSeries);
  const prompt = JSON.stringify({
    application: app.slug,
    category,
    source,
    facts,
    allowedActions,
    scope: { crashRecoveryForAllApps: true, contentBugRepair: "jellyfin_only", seriesProvided: hasSeries }
  });
  recordAgentEvent("fixer", incidentId, "started", { app: app.slug, category, source, issueNumber, facts });
  try {
    const modelFile = path.join(modelDirectory, `${incidentId}-fixer.json`);
    const cachedModel = readJson(modelFile);
    const output = cachedModel?.result
      ? { result: cachedModel.result }
      : await runGrok("fixer", `Choose a remediation for this trusted controller object:\n${prompt}`, FIX_SCHEMA);
    if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
    if (!allowedActions.includes(output.result.action)) throw new Error("model_action_not_allowed");
    const decision = facts.failedOrigins.length > 0 && allowedActions.includes("restart_origin")
      ? { ...output.result, action: "restart_origin", fixCode: "restarted", decisionSummary: "Eine konfigurierte Anwendungskomponente ist ausgefallen und wird kontrolliert neu gestartet." }
      : output.result;
    if (!cachedModel?.result) atomicWriteJson(modelFile, { result: decision, recordedAt: new Date().toISOString() });
    const noActionReason = decision.action === "no_action" ? noActionReasonFor(app, category, hasSeries) : null;
    recordAgentEvent("fixer", incidentId, "decision", {
      app: app.slug,
      issueNumber,
      ...decision,
      noActionReason,
      reasoningSummary: output.result.decisionSummary
    });
    if (decision.action === "no_action") {
      if (source === "local_watch" && facts.publicHealthy && facts.originRunning) {
        const body = `${app.displayName} ist nach dem erkannten Neustart wieder erreichbar und wurde geprüft.\n\nSolved by: Grok 4.5\n${outcomeMarker(incidentId)}`;
        await githubCommentOnce(issueNumber, incidentId, body);
        await githubWrite(`/issues/${issueNumber}`, "PATCH", { state: "closed", state_reason: "completed" });
        recordAgentEvent("fixer", incidentId, "completed", { app: app.slug, issueNumber, action: "no_action", outcome: "already_recovered" });
        return true;
      }
      recordAgentEvent("fixer", incidentId, "action", { app: app.slug, issueNumber, action: "no_action", target: "none", noActionReason });
      await githubCommentOnce(issueNumber, incidentId, outcomeComment({ action: "no_action", incidentId, appName: app.displayName, noActionReason }));
      recordAgentEvent("fixer", incidentId, "completed", { app: app.slug, issueNumber, action: "no_action", outcome: "not_executed" });
      return false;
    }
    const receiptFile = path.join(modelDirectory, `${incidentId}-action.json`);
    const receipt = readJson(receiptFile);
    const actionResult = receipt?.action === decision.action
      ? receipt.result
      : executeAction(app, decision.action, series, facts);
    if (receipt?.action !== decision.action) {
      atomicWriteJson(receiptFile, { action: decision.action, result: actionResult, recordedAt: new Date().toISOString() });
    }
    recordAgentEvent("fixer", incidentId, "action", {
      app: app.slug,
      issueNumber,
      action: decision.action,
      target: actionTarget(app, decision.action)
    });
    if (decision.action !== "no_action") await delay(10000);
    const verification = await verifyRecovery(app, category, decision.action, actionResult);
    recordAgentEvent("fixer", incidentId, "verification", { app: app.slug, issueNumber, ...verification });
    if (!verification.verified) {
      log("recovery_not_verified", { app: app.slug, issueNumber });
      await githubCommentOnce(issueNumber, incidentId, outcomeComment({ action: decision.action, incidentId, appName: app.displayName, failureCode: "recovery_not_verified" }));
      recordAgentEvent("fixer", incidentId, "failed", { app: app.slug, issueNumber, code: "recovery_not_verified" });
      return false;
    }
    if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
    await githubCommentOnce(issueNumber, incidentId, outcomeComment({ action: decision.action, incidentId, appName: app.displayName }));
    if (source === "public_form" || source === "local_watch") {
      await githubWrite(`/issues/${issueNumber}`, "PATCH", { state: "closed", state_reason: "completed" });
    }
    recordAgentEvent("fixer", incidentId, "completed", { app: app.slug, issueNumber, action: decision.action });
    log("incident_solved", { app: app.slug, issueNumber, action: decision.action });
    return true;
  } catch (error) {
    recordAgentEvent("fixer", incidentId, "failed", { app: app.slug, issueNumber, code: error.message });
    if (isSecurityInterruption(error.message) || isPaused(stateDirectory)) throw error;
    await githubCommentOnce(issueNumber, incidentId, outcomeComment({
      action: "no_action",
      incidentId,
      appName: app.displayName,
      failureCode: publicFailureCode(error.message)
    }));
    return false;
  }
}

function safeReportIssue(app, summary, id) {
  if (!/^[0-9a-f-]{36}$/u.test(id)) throw new Error("invalid_report_id");
  return {
    title: `Störungsmeldung: ${app.displayName}`,
    body: [
      "Eine Störung wurde über status.fasrv.ch gemeldet.",
      "",
      `- Anwendung: ${app.displayName}`,
      `- Kategorie: ${CATEGORY_LABELS[summary.category]}`,
      `- Referenz: ${id}`,
      "",
      "Die technische Prüfung läuft automatisch.",
      `<!-- fasrv-report:v1:${id} -->`
    ].join("\n"),
    labels: ["user-report"]
  };
}

async function findExistingReportIssue(app, id) {
  const issues = await github("/issues?state=all&labels=user-report&per_page=100");
  const marker = `<!-- fasrv-report:v1:${id} -->`;
  return issues.find((issue) => !issue.pull_request && issue.user?.login === trustedGithubUser && issue.body?.includes(marker)) ?? null;
}

async function processQueueFile(file) {
  if (isPaused(stateDirectory)) return;
  const claimed = path.join(processingDirectory, path.basename(file));
  try { fs.renameSync(file, claimed); } catch { return; }
  const report = readJson(claimed);
  const workflowStateFile = path.join(processingDirectory, `${path.basename(file, ".json")}.state.json`);
  try {
    if (!report || !appBySlug.has(report.app)) throw new Error("invalid_queued_report");
    const app = appBySlug.get(report.app);
    let workflowState = readJson(workflowStateFile);
    if (!workflowState?.summary || !workflowState?.issueNumber) {
      const summaryOutput = await summarizeReport(report);
      atomicWriteJson(path.join(modelDirectory, `${report.id}-summarizer.json`), { result: summaryOutput.result, recordedAt: new Date().toISOString() });
      const existingIssue = await findExistingReportIssue(app, report.id);
      const issue = existingIssue ?? await githubWrite("/issues", "POST", safeReportIssue(app, summaryOutput.result, report.id));
      if (issue.user?.login !== trustedGithubUser) throw new Error("untrusted_issue_author");
      markIssueSeen(issue.number);
      workflowState = { summary: summaryOutput.result, issueNumber: issue.number, stage: "issue_created" };
      atomicWriteJson(workflowStateFile, workflowState);
    }
    const solved = await analyzeAndFix({ app, category: workflowState.summary.category, issueNumber: workflowState.issueNumber, incidentId: report.id, source: "public_form", series: validateSeries(report.series) });
    atomicWriteJson(path.join(archiveDirectory, `${report.id}.json`), { ...report, summary: workflowState.summary, issueNumber: workflowState.issueNumber, solved, processedAt: new Date().toISOString() });
    fs.unlinkSync(claimed);
    fs.rmSync(workflowStateFile, { force: true });
  } catch (error) {
    log("report_processing_failed", { reportId: report?.id ?? "invalid", code: error.message });
    if (new Set(["prompt_injection", "report_contains_secret"]).has(error.message)) {
      fs.renameSync(claimed, path.join(quarantineDirectory, path.basename(claimed)));
      fs.rmSync(workflowStateFile, { force: true });
    } else if (!isPaused(stateDirectory)) {
      fs.renameSync(claimed, path.join(queueDirectory, path.basename(claimed)));
    }
  }
}

function issueLabels(issue) {
  return new Set((issue.labels ?? []).map((label) => typeof label === "string" ? label : label.name));
}

function markIssueSeen(issueNumber) {
  const seen = new Set(controllerState.seenIssues ?? []);
  seen.add(issueNumber);
  controllerState.seenIssues = [...seen].slice(-500);
  atomicWriteJson(controllerStateFile, controllerState);
}

function isAuthenticUpptimeIssue(issue, app) {
  const labels = issueLabels(issue);
  if (!labels.has("status") || !labels.has(app.slug)) return false;
  if (issue.user?.login !== trustedGithubUser) return false;
  return issue.title === `🛑 ${app.displayName} is down`
    || issue.title === `🟨 ${app.displayName} has degraded performance`;
}

function appForTrustedIssue(issue) {
  const labels = issueLabels(issue);
  const byLabel = apps.find((app) => labels.has(app.slug));
  if (byLabel) return byLabel;
  const haystack = `${issue.title ?? ""}\n${issue.body ?? ""}`.normalize("NFKC").toLocaleLowerCase("de");
  return apps.find((app) => {
    const names = [app.slug.replaceAll("-", " "), app.displayName, ...(app.aliases ?? [])]
      .map((value) => String(value).normalize("NFKC").toLocaleLowerCase("de"));
    return names.some((name) => haystack.includes(name));
  }) ?? null;
}

function categoryForIssue(issue) {
  const text = `${issue.title ?? ""}\n${issue.body ?? ""}`.toLocaleLowerCase("de");
  if (/poster|bild|image|cover|verschwommen|unscharf/u.test(text)) return "images";
  if (/anime.{0,30}(download|queue|warteschlange)|requeue/u.test(text)) return "anime_download";
  if (/playback|wiedergabe|abspielen|stream/u.test(text)) return "playback";
  if (/langsam|slow|lag|performance|timeout/u.test(text)) return "performance";
  if (/login|anmeld/u.test(text)) return "login";
  return "availability";
}

function seriesForIssue(issue) {
  const match = String(issue.body ?? "").match(/(?:Serie|Series)\s*:\s*([^\n]{1,120})/iu);
  try { return match ? validateSeries(match[1]) : ""; } catch { return ""; }
}

function localCrashIssue(app) {
  return {
    title: `🛑 ${app.displayName} crashed`,
    body: [
      `${app.displayName} wurde vom lokalen FASRV-Wächter als nicht laufend erkannt.`,
      "",
      "Die Wiederherstellung und anschließende Funktionsprüfung laufen automatisch.",
      `<!-- fasrv-local-crash:v1:${app.slug} -->`
    ].join("\n")
  };
}

async function findOpenLocalCrashIssue(app) {
  const issues = await github("/issues?state=open&per_page=100");
  const marker = `<!-- fasrv-local-crash:v1:${app.slug} -->`;
  return issues.find((issue) => !issue.pull_request && issue.user?.login === trustedGithubUser && issue.body?.includes(marker)) ?? null;
}

async function monitorLocalCrashes() {
  const now = Date.now();
  const stateMap = readOriginStateMap(apps.filter((app) => app.monitorLocal !== false).flatMap(configuredOrigins));
  for (const app of apps) {
    if (app.monitorLocal === false || configuredOrigins(app).length === 0) continue;
    const health = controllerState.localHealth[app.slug] ?? { failures: 0, issueNumber: null, lastAttemptAt: 0, componentStates: null };
    const origins = readOriginStates(app, stateMap);
    const componentStates = Object.fromEntries(origins.map((origin) => [originKey(origin), { restartCount: origin.restartCount, generation: origin.generation }]));
    if (!health.componentStates) {
      health.componentStates = componentStates;
      controllerState.localHealth[app.slug] = health;
      continue;
    }
    const restarted = origins.filter((origin) => originRestarted(origin, health.componentStates[originKey(origin)]));
    health.componentStates = componentStates;
    const allRunning = origins.every((origin) => origin.running);
    if (allRunning && restarted.length === 0) {
      health.failures = 0;
      if (health.issueNumber) {
        const issue = await github(`/issues/${health.issueNumber}`);
        const result = await probe(app);
        if (issue.state === "open" && issue.user?.login === trustedGithubUser && result.healthy) {
          const incidentId = `local-recovered-${app.slug}-${issue.number}`;
          const body = `${app.displayName} ist wieder erreichbar und wurde erneut geprüft.\n\nSolved by: Grok 4.5\n${outcomeMarker(incidentId)}`;
          await githubCommentOnce(issue.number, incidentId, body);
          await githubWrite(`/issues/${issue.number}`, "PATCH", { state: "closed", state_reason: "completed" });
          health.issueNumber = null;
        }
      }
      controllerState.localHealth[app.slug] = health;
      continue;
    }
    health.failures = allRunning ? 2 : health.failures + 1;
    controllerState.localHealth[app.slug] = health;
    atomicWriteJson(controllerStateFile, controllerState);
    if (health.failures < 2 || now - health.lastAttemptAt < 300000) continue;
    health.lastAttemptAt = now;
    let issue = health.issueNumber ? await github(`/issues/${health.issueNumber}`) : null;
    if (!issue || issue.state !== "open" || issue.user?.login !== trustedGithubUser) issue = await findOpenLocalCrashIssue(app);
    if (!issue) issue = await githubWrite("/issues", "POST", localCrashIssue(app));
    if (issue.user?.login !== trustedGithubUser) throw new Error("untrusted_issue_author");
    health.issueNumber = issue.number;
    markIssueSeen(issue.number);
    recordAgentEvent("fixer", `local-${app.slug}`, "validated", { app: app.slug, checks: ["trusted_author", "local_origin_state"] });
    const solved = await analyzeAndFix({
      app,
      category: "availability",
      issueNumber: issue.number,
      incidentId: `local-${app.slug}-${now}`,
      source: "local_watch"
    });
    if (solved) {
      health.failures = 0;
      health.issueNumber = null;
    }
    atomicWriteJson(controllerStateFile, controllerState);
  }
}

async function pollIssues() {
  const issues = await github("/issues?state=all&sort=created&direction=desc&per_page=100");
  if (freshControllerState && controllerState.seenIssues.length === 0) {
    controllerState.seenIssues = issues.filter((issue) => !issue.pull_request).map((issue) => issue.number).slice(-500);
    atomicWriteJson(controllerStateFile, controllerState);
    log("github_baseline_recorded", { issues: controllerState.seenIssues.length });
    return;
  }
  const seen = new Set(controllerState.seenIssues);
  for (const issue of issues.reverse()) {
    if (issue.pull_request || seen.has(issue.number)) continue;
    if (issue.user?.login !== trustedGithubUser) {
      log("issue_ignored_untrusted_author", { issueNumber: issue.number, author: issue.user?.login ?? "unknown" });
      markIssueSeen(issue.number);
      continue;
    }
    if (issue.state === "open" && new Date(issue.created_at) >= new Date(controllerState.startedAt)) {
      const trustedIssueText = `${issue.title ?? ""}\n${issue.body ?? ""}`;
      const secret = scanner.scan(trustedIssueText);
      const injection = detectPromptInjection(trustedIssueText);
      if (secret || injection) {
        log("issue_isolated", { issueNumber: issue.number, code: secret ?? injection });
      } else {
        const upptimeApp = apps.find((candidate) => isAuthenticUpptimeIssue(issue, candidate));
        const app = upptimeApp ?? appForTrustedIssue(issue);
        if (app) {
          await analyzeAndFix({
            app,
            category: upptimeApp ? (issue.title.includes("degraded performance") ? "performance" : "availability") : categoryForIssue(issue),
            issueNumber: issue.number,
            incidentId: `${upptimeApp ? "upptime" : "github"}-${issue.number}`,
            source: upptimeApp ? "upptime" : "github",
            series: app.slug === "jellyfin" ? seriesForIssue(issue) : ""
          });
        } else {
          log("issue_ignored_unknown_application", { issueNumber: issue.number });
        }
      }
    }
    markIssueSeen(issue.number);
  }
}

async function cycle() {
  if (isPaused(stateDirectory)) return;
  for (const file of fs.readdirSync(queueDirectory).filter((name) => name.endsWith(".json")).sort()) {
    await processQueueFile(path.join(queueDirectory, file));
    if (isPaused(stateDirectory)) return;
  }
  await monitorLocalCrashes();
  await pollIssues();
}

log("worker_started", { repository, trustedGithubUser, apps: apps.length });
while (true) {
  try { await cycle(); } catch (error) { log("cycle_failed", { code: error.message }); }
  await delay(pollSeconds * 1000);
}
