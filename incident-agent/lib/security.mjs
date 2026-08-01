import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const INJECTION_RULES = [
  ["role_override", /(?:^|\s)(?:system|developer|assistant|user)\s*:/iu],
  ["instruction_override", /(?:ignore|disregard|forget|override|bypass|ignoriere|vergiss|ueberschreibe|überschreibe).{0,50}(?:instruction|prompt|rule|message|anweisung|regel|vorgabe)/iu],
  ["prompt_attack", /(?:prompt\s*injection|jailbreak|system\s*prompt|developer\s*message|hidden\s*instruction|dan\s*mode)/iu],
  ["secret_request", /(?:show|print|reveal|leak|exfiltrate|read|zeige|drucke|verrate|lies).{0,50}(?:password|passwort|secret|token|credential|api[ _-]?key|\.env|auth\.json)/iu],
  ["tool_request", /(?:run|execute|invoke|call|fuehre|führe|starte).{0,40}(?:shell|bash|command|tool|curl|wget|sudo|cat\s)/iu],
  ["code_markup", /```|`[^`]{2,}`|<\/?(?:script|system|assistant|tool|prompt)\b|\$\{|\{\{|\}\}/iu],
  ["sensitive_path", /(?:\/etc\/|\/root\/|\/proc\/|\/sys\/|\.\.\/|file:\/\/)/iu],
  ["encoded_payload", /(?:[A-Za-z0-9+/]{80,}={0,2}|[A-Fa-f0-9]{96,})/u],
  ["bidi_control", /[\u202A-\u202E\u2066-\u2069]/u],
  ["control_character", /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u]
];

const GENERIC_SECRET_RULES = [
  ["private_key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u],
  ["known_token_prefix", /(?:github_pat_|gh[opsu]_|cfat_|xai-|sk-)[A-Za-z0-9_\-]{12,}/u],
  ["jwt", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u],
  ["secret_assignment", /(?:password|passwd|passwort|secret|token|api[ _-]?key)\s*[:=]\s*["']?[^\s"']{6,}/iu],
  ["authorization_header", /authorization\s*:\s*(?:bearer|basic)\s+\S+/iu]
];

export function normalizeText(value, maxLength) {
  if (typeof value !== "string") throw new Error("invalid_type");
  const normalized = value.normalize("NFKC").replace(/\r\n?/gu, "\n").trim();
  if (!normalized || normalized.length > maxLength) throw new Error("invalid_length");
  return normalized;
}

export function detectPromptInjection(value) {
  const text = String(value ?? "");
  for (const [code, rule] of INJECTION_RULES) {
    if (rule.test(text)) return code;
  }
  return null;
}

export function validateDescription(value) {
  const text = normalizeText(value, 500).replace(/\s+/gu, " ");
  if (text.length < 8) throw new Error("description_too_short");
  const injection = detectPromptInjection(text);
  if (injection) throw Object.assign(new Error("prompt_injection"), { code: injection });
  if (!/^[\p{L}\p{N}\p{M}\s.,!?():;'"%+\-&]+$/u.test(text)) throw new Error("unsupported_characters");
  return text;
}

export function validateSeries(value) {
  if (value === undefined || value === null || value === "") return "";
  const text = normalizeText(value, 120).replace(/\s+/gu, " ");
  const injection = detectPromptInjection(text);
  if (injection) throw Object.assign(new Error("prompt_injection"), { code: injection });
  if (!/^[\p{L}\p{N}\p{M}\s.:'\-&]+$/u.test(text)) throw new Error("unsupported_series_characters");
  return text;
}

function stringsFromJson(value, output = []) {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) value.forEach((item) => stringsFromJson(item, output));
  else if (value && typeof value === "object") Object.values(value).forEach((item) => stringsFromJson(item, output));
  return output;
}

function stringsFromEnv(content) {
  return content.split(/\r?\n/u).flatMap((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) return [];
    let value = trimmed.slice(trimmed.indexOf("=") + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    return value ? [value] : [];
  });
}

export class SecretScanner {
  constructor(values = []) {
    this.values = [...new Set(values.filter((value) => typeof value === "string" && value.length >= 6))];
  }

  static fromPaths(paths) {
    const values = [];
    for (const candidate of paths) {
      if (!fs.existsSync(candidate)) continue;
      const stat = fs.statSync(candidate);
      const files = stat.isDirectory()
        ? fs.readdirSync(candidate).map((name) => path.join(candidate, name)).filter((file) => fs.statSync(file).isFile())
        : [candidate];
      for (const file of files) {
        const content = fs.readFileSync(file, "utf8");
        if (file.endsWith(".json")) {
          try { values.push(...stringsFromJson(JSON.parse(content))); } catch { /* ignored: generic rules still apply */ }
        } else {
          values.push(...stringsFromEnv(content));
        }
      }
    }
    return new SecretScanner(values);
  }

  scan(value) {
    const text = String(value ?? "");
    for (const secret of this.values) {
      if (text.includes(secret)) return "known_secret";
    }
    for (const [code, rule] of GENERIC_SECRET_RULES) {
      if (rule.test(text)) return code;
    }
    return null;
  }
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
