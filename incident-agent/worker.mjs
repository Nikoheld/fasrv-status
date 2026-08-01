import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { atomicWriteJson, ensureDirectory, isPaused, readJson, tripCircuitBreaker } from "./lib/runtime.mjs";
import { detectPromptInjection, SecretScanner, validateDescription, validateSeries } from "./lib/security.mjs";
import { allowedActionsFor, isSecurityInterruption, noActionReasonFor, outcomeComment, outcomeMarker } from "./lib/remediation.mjs";

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
const githubToken = fs.readFileSync(process.env.GITHUB_TOKEN_FILE ?? "/etc/fasrv-incident-agent/github-token", "utf8").trim();
const grokBinary = process.env.GROK_BINARY ?? "/home/codexweb/.grok/bin/grok";
const jellyfinRemediationHelper = process.env.JELLYFIN_REMEDIATION_HELPER ?? "/usr/local/sbin/fasrv-jellyfin-remediate";
const pollSeconds = Number(process.env.POLL_SECONDS ?? 30);
const apps = JSON.parse(fs.readFileSync(appConfig, "utf8"));
const appBySlug = new Map(apps.map((app) => [app.slug, app]));
const scanner = SecretScanner.fromPaths((process.env.SECRET_PATHS ?? "/srv/codex-web/shared-credentials:/home/codexweb/.grok/auth.json:/etc/fasrv-incident-agent/github-token").split(":"));
const controllerStateFile = path.join(stateDirectory, "controller.json");
const freshControllerState = !fs.existsSync(controllerStateFile);
let controllerState = readJson(controllerStateFile, { startedAt: new Date().toISOString(), seenIssues: [] });

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
  const injection = detectPromptInjection(serialized);
  if (injection) {
    stopForSecurity(injection, "github_output_gate");
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
          stopForSecurity(injection, `${kind}_injection_gate`);
          return reject(new Error("security_gate"));
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
    stopForSecurity(secret, "queued_report_secret_gate");
    throw new Error("security_gate");
  }
  const injection = detectPromptInjection(untrustedInput);
  if (injection) {
    stopForSecurity(injection, "queued_report");
    throw new Error("security_gate");
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
      stopForSecurity("model_marked_suspicious", "summarizer");
      throw new Error("security_gate");
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
  try {
    const response = await fetch(app.url, { redirect: "manual", signal: AbortSignal.timeout(10000) });
    return { healthy: app.expectedStatusCodes.includes(response.status), status: response.status, latencyMs: Date.now() - started };
  } catch {
    return { healthy: false, status: 0, latencyMs: Date.now() - started };
  }
}

function localFacts(app, publicProbe) {
  const facts = {
    publicHealthy: publicProbe.healthy,
    publicStatusClass: publicProbe.status ? `${Math.floor(publicProbe.status / 100)}xx` : "network_error",
    publicLatencyClass: publicProbe.latencyMs < 1000 ? "fast" : publicProbe.latencyMs < 3000 ? "moderate" : "slow",
    originConfigured: Boolean(app.container || app.unit),
    originRunning: null,
    proxyConfigurationValid: spawnSync("sudo", ["-n", "nginx", "-t"], { stdio: "ignore" }).status === 0
  };
  if (app.container) facts.originRunning = spawnSync("sudo", ["-n", "docker", "inspect", "-f", "{{.State.Running}}", app.container], { encoding: "utf8" }).stdout.trim() === "true";
  if (app.unit) facts.originRunning = spawnSync("sudo", ["-n", "systemctl", "is-active", "--quiet", app.unit]).status === 0;
  return facts;
}

function executeAction(app, action, series) {
  if (!app.allowedActions.includes(action)) throw new Error("action_not_allowed");
  if (action === "no_action") return { accepted: true, target: "none", latencyMs: 0 };
  const started = Date.now();
  let result;
  if (action === "restart_origin" && app.container) result = spawnSync("sudo", ["-n", "docker", "restart", app.container], { stdio: "ignore", timeout: 120000 });
  else if (action === "restart_origin" && app.unit) result = spawnSync("sudo", ["-n", "systemctl", "restart", app.unit], { stdio: "ignore", timeout: 120000 });
  else if (action === "reload_proxy") {
    if (spawnSync("sudo", ["-n", "nginx", "-t"], { stdio: "ignore" }).status !== 0) throw new Error("nginx_config_invalid");
    result = spawnSync("sudo", ["-n", "systemctl", "reload", "nginx"], { stdio: "ignore", timeout: 30000 });
  } else if (action === "refresh_jellyfin_images" || action === "requeue_hianime") {
    const helperAction = action === "refresh_jellyfin_images" ? "refresh-images" : "requeue-hianime";
    result = spawnSync("sudo", ["-n", jellyfinRemediationHelper, helperAction, series], { encoding: "utf8", timeout: 120000 });
    if (result.status !== 0) {
      const code = readJsonFromString(result.stdout)?.code;
      const allowedCodes = new Set(["hianime_match_not_found", "jellyfin_item_not_found"]);
      throw new Error(allowedCodes.has(code) ? code : "helper_failed");
    }
  } else throw new Error("action_unavailable");
  if (result.status !== 0) throw new Error("action_failed");
  return { accepted: true, target: actionTarget(app, action), latencyMs: Date.now() - started };
}

function readJsonFromString(value) {
  try { return JSON.parse(String(value ?? "")); } catch { return null; }
}

function actionTarget(app, action) {
  if (action === "restart_origin") return app.container ? "container" : "systemd_service";
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
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
    if (attempt) await delay(5000);
    const result = await probe(app);
    checks.push({ attempt: attempt + 1, healthy: result.healthy, status: result.status, latencyMs: result.latencyMs });
    if (!result.healthy || (category === "performance" && result.latencyMs >= 3000)) return { verified: false, checks };
  }
  return { verified: true, checks };
}

async function githubCommentOnce(issueNumber, incidentId, body) {
  const marker = outcomeMarker(incidentId);
  const comments = await github(`/issues/${issueNumber}/comments?per_page=100`);
  if (comments.some((comment) => String(comment.body ?? "").includes(marker))) return false;
  await githubWrite(`/issues/${issueNumber}/comments`, "POST", { body });
  return true;
}

function publicFailureCode(code) {
  const allowed = new Set(["action_failed", "helper_failed", "hianime_match_not_found", "jellyfin_item_not_found", "recovery_not_verified"]);
  return allowed.has(code) ? code : "helper_failed";
}

async function analyzeAndFix({ app, category, issueNumber, incidentId, source, series = "" }) {
  const initialProbe = await probe(app);
  const facts = localFacts(app, initialProbe);
  const hasSeries = Boolean(series);
  const allowedActions = allowedActionsFor(app, category, hasSeries);
  const prompt = JSON.stringify({ application: app.slug, category, source, facts, allowedActions, scope: { jellyfinOnly: true, seriesProvided: hasSeries } });
  recordAgentEvent("fixer", incidentId, "started", { app: app.slug, category, source, issueNumber, facts });
  try {
    const modelFile = path.join(modelDirectory, `${incidentId}-fixer.json`);
    const cachedModel = readJson(modelFile);
    const output = cachedModel?.result
      ? { result: cachedModel.result }
      : await runGrok("fixer", `Choose a remediation for this trusted controller object:\n${prompt}`, FIX_SCHEMA);
    if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
    if (!allowedActions.includes(output.result.action)) throw new Error("model_action_not_allowed");
    if (!cachedModel?.result) atomicWriteJson(modelFile, { result: output.result, recordedAt: new Date().toISOString() });
    const noActionReason = output.result.action === "no_action" ? noActionReasonFor(app, category, hasSeries) : null;
    recordAgentEvent("fixer", incidentId, "decision", {
      app: app.slug,
      issueNumber,
      ...output.result,
      noActionReason,
      reasoningSummary: output.result.decisionSummary
    });
    if (output.result.action === "no_action") {
      recordAgentEvent("fixer", incidentId, "action", { app: app.slug, issueNumber, action: "no_action", target: "none", noActionReason });
      await githubCommentOnce(issueNumber, incidentId, outcomeComment({ action: "no_action", incidentId, noActionReason }));
      recordAgentEvent("fixer", incidentId, "completed", { app: app.slug, issueNumber, action: "no_action", outcome: "not_executed" });
      return false;
    }
    const receiptFile = path.join(modelDirectory, `${incidentId}-action.json`);
    const receipt = readJson(receiptFile);
    const actionResult = receipt?.action === output.result.action
      ? receipt.result
      : executeAction(app, output.result.action, series);
    if (receipt?.action !== output.result.action) {
      atomicWriteJson(receiptFile, { action: output.result.action, result: actionResult, recordedAt: new Date().toISOString() });
    }
    recordAgentEvent("fixer", incidentId, "action", {
      app: app.slug,
      issueNumber,
      action: output.result.action,
      target: actionTarget(app, output.result.action)
    });
    if (output.result.action !== "no_action") await delay(10000);
    const verification = await verifyRecovery(app, category, output.result.action, actionResult);
    recordAgentEvent("fixer", incidentId, "verification", { app: app.slug, issueNumber, ...verification });
    if (!verification.verified) {
      log("recovery_not_verified", { app: app.slug, issueNumber });
      await githubCommentOnce(issueNumber, incidentId, outcomeComment({ action: output.result.action, incidentId, failureCode: "recovery_not_verified" }));
      recordAgentEvent("fixer", incidentId, "failed", { app: app.slug, issueNumber, code: "recovery_not_verified" });
      return false;
    }
    if (isPaused(stateDirectory)) throw new Error("pipeline_paused");
    await githubCommentOnce(issueNumber, incidentId, outcomeComment({ action: output.result.action, incidentId }));
    if (source === "public_form") await githubWrite(`/issues/${issueNumber}`, "PATCH", { state: "closed", state_reason: "completed" });
    recordAgentEvent("fixer", incidentId, "completed", { app: app.slug, issueNumber, action: output.result.action });
    log("incident_solved", { app: app.slug, issueNumber, action: output.result.action });
    return true;
  } catch (error) {
    recordAgentEvent("fixer", incidentId, "failed", { app: app.slug, issueNumber, code: error.message });
    if (isSecurityInterruption(error.message) || isPaused(stateDirectory)) throw error;
    await githubCommentOnce(issueNumber, incidentId, outcomeComment({
      action: "no_action",
      incidentId,
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
    labels: ["user-report", app.slug]
  };
}

async function findExistingReportIssue(app, id) {
  const issues = await github(`/issues?state=all&labels=user-report,${encodeURIComponent(app.slug)}&per_page=100`);
  const marker = `<!-- fasrv-report:v1:${id} -->`;
  return issues.find((issue) => !issue.pull_request && issue.body?.includes(marker)) ?? null;
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
      workflowState = { summary: summaryOutput.result, issueNumber: issue.number, stage: "issue_created" };
      atomicWriteJson(workflowStateFile, workflowState);
    }
    const solved = await analyzeAndFix({ app, category: workflowState.summary.category, issueNumber: workflowState.issueNumber, incidentId: report.id, source: "public_form", series: validateSeries(report.series) });
    atomicWriteJson(path.join(archiveDirectory, `${report.id}.json`), { ...report, summary: workflowState.summary, issueNumber: workflowState.issueNumber, solved, processedAt: new Date().toISOString() });
    fs.unlinkSync(claimed);
    fs.rmSync(workflowStateFile, { force: true });
  } catch (error) {
    log("report_processing_failed", { reportId: report?.id ?? "invalid", code: error.message });
    if (!isPaused(stateDirectory)) fs.renameSync(claimed, path.join(queueDirectory, path.basename(claimed)));
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function isAuthenticUpptimeIssue(issue, app) {
  const labels = new Set(issue.labels.map((label) => typeof label === "string" ? label : label.name));
  if (!labels.has("status") || !labels.has(app.slug)) return false;
  if (issue.user?.login !== "Nikoheld" || issue.title !== `🛑 ${app.displayName} is down`) return false;
  const bodyPattern = new RegExp(
    "^In \\[`[0-9a-f]{7}`\\]\\(https://github\\.com/Nikoheld/fasrv-status/commit/[0-9a-f]{40}\\n?\\), "
      + `${escapeRegex(app.displayName)} \\(${escapeRegex(app.url)}\\) was \\*\\*down\\*\\*:\\n`
      + "- HTTP code: \\d{1,3}\\n- Response time: \\d+ ms\\n?$",
    "u"
  );
  return bodyPattern.test(issue.body ?? "");
}

async function pollIssues() {
  const issues = await github("/issues?state=all&sort=created&direction=desc&per_page=30");
  if (freshControllerState && controllerState.seenIssues.length === 0) {
    controllerState.seenIssues = issues.filter((issue) => !issue.pull_request).map((issue) => issue.number).slice(-500);
    atomicWriteJson(controllerStateFile, controllerState);
    log("github_baseline_recorded", { issues: controllerState.seenIssues.length });
    return;
  }
  const seen = new Set(controllerState.seenIssues);
  for (const issue of issues.reverse()) {
    if (issue.pull_request || seen.has(issue.number)) continue;
    const app = apps.find((candidate) => isAuthenticUpptimeIssue(issue, candidate));
    if (app) {
      await analyzeAndFix({ app, category: "availability", issueNumber: issue.number, incidentId: `upptime-${issue.number}`, source: "upptime" });
    } else if (new Date(issue.created_at) >= new Date(controllerState.startedAt)) {
      const untrustedIssue = `${issue.title ?? ""}\n${issue.body ?? ""}`;
      const secret = scanner.scan(untrustedIssue);
      if (secret) {
        stopForSecurity(secret, "github_issue_secret_gate");
        return;
      }
      const injection = detectPromptInjection(untrustedIssue);
      if (injection) {
        stopForSecurity(injection, "github_issue");
        return;
      }
    }
    seen.add(issue.number);
    controllerState.seenIssues = [...seen].slice(-500);
    atomicWriteJson(controllerStateFile, controllerState);
  }
}

async function cycle() {
  if (isPaused(stateDirectory)) return;
  for (const file of fs.readdirSync(queueDirectory).filter((name) => name.endsWith(".json")).sort()) {
    await processQueueFile(path.join(queueDirectory, file));
    if (isPaused(stateDirectory)) return;
  }
  await pollIssues();
}

log("worker_started", { repository, apps: apps.length });
while (true) {
  try { await cycle(); } catch (error) { log("cycle_failed", { code: error.message }); }
  await delay(pollSeconds * 1000);
}
