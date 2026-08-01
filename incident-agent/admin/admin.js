(() => {
  "use strict";

  const elements = {
    toggle: document.getElementById("pipeline-toggle"),
    pipelineLabel: document.getElementById("pipeline-label"),
    banner: document.getElementById("pause-banner"),
    pauseDetail: document.getElementById("pause-detail"),
    connection: document.getElementById("connection-state"),
    updated: document.getElementById("updated-at"),
    intakeEvents: document.getElementById("intake-events"),
    fixerEvents: document.getElementById("fixer-events"),
    intakeState: document.getElementById("intake-state"),
    fixerState: document.getElementById("fixer-state")
  };
  let controlToken = "";
  let changing = false;

  const labels = {
    started: "Analyse gestartet",
    completed: "Abgeschlossen",
    decision: "Entscheidung getroffen",
    action: "Aktion ausgeführt",
    verification: "Health-Checks beendet",
    failed: "Gestoppt"
  };

  const actionLabels = {
    no_action: "Kein Eingriff",
    restart_origin: "Dienst neu starten",
    reload_proxy: "Proxy neu laden",
    restart_tunnel: "Verbindung neu starten"
  };

  function formatTime(value) {
    return new Intl.DateTimeFormat("de-CH", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
  }

  function detailLines(event) {
    const lines = [];
    if (event.summary) lines.push(event.summary);
    if (event.category) lines.push(`Kategorie: ${event.category}`);
    if (event.severity) lines.push(`Priorität: ${event.severity}`);
    if (event.action) lines.push(`Aktion: ${actionLabels[event.action] ?? event.action}`);
    if (event.facts) {
      lines.push(`Öffentlich: ${event.facts.publicHealthy ? "erreichbar" : "gestört"}`);
      if (event.facts.originRunning !== null) lines.push(`Dienst: ${event.facts.originRunning ? "aktiv" : "inaktiv"}`);
      lines.push(`Proxy: ${event.facts.proxyConfigurationValid ? "gültig" : "fehlerhaft"}`);
    }
    if (typeof event.verified === "boolean") lines.push(event.verified ? "3 Prüfungen bestanden" : "Nicht ausreichend verifiziert");
    if (event.code) lines.push(`Status: ${event.code}`);
    return lines;
  }

  function renderEvents(agent, events, list, state) {
    const filtered = events.filter((event) => event.agent === agent).slice(-30).reverse();
    list.replaceChildren();
    if (!filtered.length) {
      const empty = document.createElement("li");
      empty.className = "timeline__empty";
      empty.textContent = "Noch keine Ereignisse";
      list.append(empty);
      state.textContent = "Bereit";
      state.dataset.active = "false";
      return;
    }
    const active = filtered[0].stage === "started";
    state.textContent = active ? "Arbeitet" : "Bereit";
    state.dataset.active = String(active);
    for (const event of filtered) {
      const item = document.createElement("li");
      item.className = "timeline__item";
      const top = document.createElement("div");
      top.className = "timeline__top";
      const title = document.createElement("strong");
      title.textContent = labels[event.stage] ?? event.stage;
      const time = document.createElement("time");
      time.dateTime = event.time;
      time.textContent = formatTime(event.time);
      top.append(title, time);
      const app = document.createElement("p");
      app.className = "timeline__app";
      app.textContent = event.app ?? "System";
      item.append(top, app);
      for (const line of detailLines(event)) {
        const detail = document.createElement("p");
        detail.className = "timeline__detail";
        detail.textContent = line;
        item.append(detail);
      }
      list.append(item);
    }
  }

  function render(snapshot) {
    controlToken = snapshot.controlToken;
    elements.toggle.checked = !snapshot.paused;
    elements.toggle.disabled = changing;
    elements.pipelineLabel.textContent = snapshot.paused ? "Blockiert" : "Automatik aktiv";
    elements.banner.hidden = !snapshot.paused;
    elements.pauseDetail.textContent = snapshot.paused
      ? `${snapshot.pause?.reasonCode ?? "security_pause"} · ${snapshot.pause?.source ?? "security"}`
      : "";
    renderEvents("intake", snapshot.events, elements.intakeEvents, elements.intakeState);
    renderEvents("fixer", snapshot.events, elements.fixerEvents, elements.fixerState);
    elements.connection.textContent = "Verbunden";
    elements.updated.dateTime = snapshot.serverTime;
    elements.updated.textContent = formatTime(snapshot.serverTime);
  }

  async function refresh() {
    if (changing) return;
    try {
      const response = await fetch("/api/snapshot", { cache: "no-store" });
      if (!response.ok) throw new Error("snapshot_failed");
      render(await response.json());
    } catch {
      elements.connection.textContent = "Verbindung unterbrochen";
      elements.toggle.disabled = true;
    }
  }

  elements.toggle.addEventListener("change", async () => {
    changing = true;
    elements.toggle.disabled = true;
    try {
      const action = elements.toggle.checked ? "unblock" : "block";
      const response = await fetch("/api/control", {
        method: "POST",
        headers: { "content-type": "application/json", "x-control-token": controlToken },
        body: JSON.stringify({ action })
      });
      if (!response.ok) throw new Error("control_failed");
    } catch {
      elements.connection.textContent = "Steuerung fehlgeschlagen";
    } finally {
      changing = false;
      await refresh();
    }
  });

  refresh();
  setInterval(refresh, 2000);
})();
