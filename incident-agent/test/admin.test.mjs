import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForServer(url) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
    } catch { /* server still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("admin_server_not_ready");
}

test("admin API blocks, rejects cross-origin control, and unblocks", async (context) => {
  const port = await freePort();
  const stateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "fasrv-admin-test-"));
  for (const name of ["events", "processing", "queue"]) fs.mkdirSync(path.join(stateDirectory, name));
  const child = spawn(process.execPath, [path.resolve("admin-server.mjs")], {
    cwd: path.resolve("."),
    env: { ...process.env, PORT: String(port), STATE_DIRECTORY: stateDirectory, STATIC_DIRECTORY: path.resolve("admin") },
    stdio: "ignore"
  });
  context.after(() => {
    child.kill("SIGTERM");
    fs.rmSync(stateDirectory, { recursive: true, force: true });
  });

  const origin = `http://127.0.0.1:${port}`;
  const snapshot = await waitForServer(`${origin}/api/snapshot`);
  assert.equal(snapshot.paused, false);
  assert.ok(snapshot.controlToken.length > 20);

  const unauthorized = await fetch(`${origin}/api/control`, {
    method: "POST",
    headers: { origin: "http://invalid.example", "content-type": "application/json" },
    body: JSON.stringify({ action: "block" })
  });
  assert.equal(unauthorized.status, 403);

  const headers = { origin, "content-type": "application/json", "x-control-token": snapshot.controlToken };
  const blocked = await fetch(`${origin}/api/control`, { method: "POST", headers, body: JSON.stringify({ action: "block" }) });
  assert.deepEqual(await blocked.json(), { paused: true });
  const unblocked = await fetch(`${origin}/api/control`, { method: "POST", headers, body: JSON.stringify({ action: "unblock" }) });
  assert.deepEqual(await unblocked.json(), { paused: false });
});
