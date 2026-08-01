import fs from "node:fs";
import net from "node:net";
import path from "node:path";

export function ensureDirectory(directory, mode = 0o700) {
  const existed = fs.existsSync(directory);
  fs.mkdirSync(directory, { recursive: true, mode });
  if (!existed) fs.chmodSync(directory, mode);
}

export function atomicWriteJson(file, value, mode = 0o600) {
  ensureDirectory(path.dirname(file));
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value)}\n`, { mode });
  fs.renameSync(temporary, file);
  fs.chmodSync(file, mode);
}

export function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}

export function isPaused(stateDirectory) {
  return fs.existsSync(path.join(stateDirectory, "PAUSED"));
}

function sendAlertEmail(reasonCode, source) {
  const recipient = process.env.ALERT_EMAIL ?? "fabio@fasrv.ch";
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$/u.test(recipient)) return;
  const safeReason = String(reasonCode).replace(/[^a-z0-9_-]/giu, "_").slice(0, 80);
  const safeSource = String(source).replace(/[^a-z0-9_-]/giu, "_").slice(0, 80);
  const subject = "FASRV Incident Agent pausiert";
  const message = [
    "From: incident-agent@fasrv.ch",
    `To: ${recipient}`,
    `Subject: ${subject}`,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    "Die automatische Issue-Verarbeitung wurde sicherheitshalber gestoppt.",
    `Grundcode: ${safeReason}`,
    `Quelle: ${safeSource}`,
    "Es wurden nach der Erkennung keine GitHub-Inhalte veröffentlicht.",
    "Zum Fortsetzen muss die PAUSED-Datei nach manueller Prüfung entfernt werden.",
    ""
  ].join("\r\n");
  const socket = net.createConnection({ host: "127.0.0.1", port: 25 });
  socket.setTimeout(10000);
  let phase = "greeting";
  let buffer = "";
  const send = (line) => socket.write(`${line}\r\n`);
  socket.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    const lines = buffer.split("\r\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (phase === "greeting" && /^220 /u.test(line)) { phase = "ehlo"; send("EHLO pve.fasrv.ch"); }
      else if (phase === "ehlo" && /^250 /u.test(line)) { phase = "mail"; send("MAIL FROM:<incident-agent@fasrv.ch>"); }
      else if (phase === "mail" && /^250 /u.test(line)) { phase = "rcpt"; send(`RCPT TO:<${recipient}>`); }
      else if (phase === "rcpt" && /^250 /u.test(line)) { phase = "data"; send("DATA"); }
      else if (phase === "data" && /^354 /u.test(line)) { phase = "body"; socket.write(`${message}\r\n.\r\n`); }
      else if (phase === "body" && /^250 /u.test(line)) { phase = "quit"; send("QUIT"); }
      else if (phase === "quit" && /^221 /u.test(line)) socket.end();
      else if (/^[45]\d\d /u.test(line)) socket.destroy();
    }
  });
  socket.on("timeout", () => socket.destroy());
  socket.on("error", () => {});
}

export function tripCircuitBreaker(stateDirectory, reasonCode, source) {
  ensureDirectory(stateDirectory);
  const pauseFile = path.join(stateDirectory, "PAUSED");
  if (!fs.existsSync(pauseFile)) {
    atomicWriteJson(pauseFile, { pausedAt: new Date().toISOString(), reasonCode, source }, 0o640);
    sendAlertEmail(reasonCode, source);
  }
}

export async function readRequestBody(request, maximumBytes = 4096) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximumBytes) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}
