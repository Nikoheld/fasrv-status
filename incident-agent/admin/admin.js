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
    validated: "Sicherheitsprüfung bestanden",
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
    restart_tunnel: "Verbindung neu starten",
    refresh_jellyfin_images: "Bilder und Metadaten aktualisieren",
    requeue_hianime: "Anime-Download erneut einreihen"
  };

  const problemLabels = {
    unavailable: "Öffentlich nicht erreichbar",
    slow: "Antwort zu langsam",
    proxy: "Proxy gestört",
    origin: "Anwendungsdienst gestört",
    image_metadata: "Bilder oder Metadaten fehlerhaft",
    anime_download: "Anime-Download fehlgeschlagen",
    unknown: "Ursache nicht eindeutig"
  };

  const fixLabels = {
    recovered: "Ohne Eingriff erholt",
    restarted: "Dienst neu gestartet",
    proxy_reloaded: "Proxy neu geladen",
    image_refresh_started: "Bildaktualisierung gestartet",
    anime_requeued: "Download erneut eingereiht",
    not_executed: "Nicht automatisch ausgeführt",
    no_change: "Keine Änderung"
  };

  const targetLabels = {
    none: "Kein System verändert",
    container: "Anwendungs-Container",
    systemd_service: "Anwendungsdienst",
    origin_components: "Anwendungs-Komponenten",
    nginx_proxy: "Nginx-Proxy",
    cloudflare_tunnel: "Cloudflare-Tunnel",
    jellyfin_library: "Jellyfin-Bibliothek",
    hianime_queue: "HiAnime-Warteschlange"
  };

  const securityCheckLabels = {
    format: "Format",
    secret_scan: "Zugangsdaten",
    prompt_injection: "Prompt Injection",
    trusted_author: "Vertrauenswürdiger GitHub-Autor",
    local_origin_state: "Lokaler Komponentenstatus"
  };

  const categoryLabels = {
    availability: "Erreichbarkeit",
    login: "Anmeldung",
    playback: "Wiedergabe",
    performance: "Geschwindigkeit",
    images: "Bilder und Metadaten",
    anime_download: "Anime-Download",
    content: "Inhalt",
    other: "Allgemeine Störung"
  };

  const severityLabels = {
    low: "Niedrig",
    medium: "Mittel",
    high: "Hoch"
  };

  const statusLabels = {
    security_gate: "Durch Sicherheitsbarriere gestoppt",
    pipeline_paused: "Durch Administrator gestoppt",
    recovery_not_verified: "Wiederherstellung nicht bestätigt"
  };

  const noActionLabels = {
    unsupported_application: "Automatische Reparaturen sind auf Jellyfin begrenzt",
    unsupported_category: "Fehlerklasse ist nicht für automatische Reparaturen freigegeben",
    missing_series: "Für den erneuten Download fehlt der Serienname",
    insufficient_evidence: "Kein sicherer Eingriff durch die Diagnose begründet"
  };

  function formatTime(value) {
    return new Intl.DateTimeFormat("de-CH", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
  }

  function detailLines(event) {
    const lines = [];
    if (event.code === "security_gate") {
      lines.push({
        label: "Schutzentscheidung",
        value: "Die Sicherheitsbewertung erkannte auffällige Eingabemuster. Der Vorgang wurde vor jeder Veröffentlichung gestoppt.",
        emphasis: true
      });
    }
    if (event.summary) lines.push({ label: "Ergebnis", value: event.summary });
    if (event.reasoningSummary) lines.push({ label: "Begründung", value: event.reasoningSummary, emphasis: true });
    if (event.category) lines.push({ label: "Kategorie", value: categoryLabels[event.category] ?? event.category });
    if (event.severity) lines.push({ label: "Priorität", value: severityLabels[event.severity] ?? event.severity });
    if (event.problemCode) lines.push({ label: "Diagnose", value: problemLabels[event.problemCode] ?? event.problemCode });
    if (event.fixCode) lines.push({ label: "Erwartetes Ergebnis", value: fixLabels[event.fixCode] ?? event.fixCode });
    if (event.action) lines.push({ label: "Aktion", value: actionLabels[event.action] ?? event.action });
    if (event.noActionReason) lines.push({ label: "Nicht ausgeführt", value: noActionLabels[event.noActionReason] ?? event.noActionReason });
    if (event.target) lines.push({ label: "Ziel", value: targetLabels[event.target] ?? event.target });
    if (event.issueNumber) lines.push({ label: "Issue", value: `#${event.issueNumber}` });
    if (event.facts) {
      lines.push({ label: "Öffentlich", value: `${event.facts.publicHealthy ? "erreichbar" : "gestört"}, ${event.facts.publicStatusClass}, ${event.facts.publicLatencyClass}` });
      if (event.facts.originRunning !== null) lines.push({ label: "Dienst", value: event.facts.originRunning ? "aktiv" : "inaktiv" });
      lines.push({ label: "Proxy-Konfiguration", value: event.facts.proxyConfigurationValid ? "gültig" : "fehlerhaft" });
    }
    if (Array.isArray(event.checks) && event.checks.every((check) => typeof check === "string")) {
      lines.push({ label: "Geprüft", value: event.checks.map((check) => securityCheckLabels[check] ?? check).join(", ") });
    }
    if (Array.isArray(event.checks) && event.checks.every((check) => typeof check === "object")) {
      for (const check of event.checks) {
        if (check.kind === "image") {
          lines.push({
            label: "Bildprüfung",
            value: check.healthy
              ? `bestanden, Poster ${check.primary.width}×${check.primary.height}, Hintergrund ${check.backdrop.width}×${check.backdrop.height}, Darstellung scharf`
              : "fehlgeschlagen"
          });
          continue;
        }
        lines.push({
          label: `Health-Check ${check.attempt}`,
          value: `${check.healthy ? "bestanden" : "fehlgeschlagen"}, HTTP ${check.status || "Netzwerkfehler"}, ${check.latencyMs} ms`
        });
      }
    }
    if (typeof event.verified === "boolean") lines.push({ label: "Verifikation", value: event.verified ? "Bestanden" : "Nicht ausreichend" });
    if (event.code) lines.push({ label: "Status", value: statusLabels[event.code] ?? event.code });
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
    const active = !["completed", "failed"].includes(filtered[0].stage);
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
        detail.className = line.emphasis ? "timeline__detail timeline__detail--reasoning" : "timeline__detail";
        const detailLabel = document.createElement("strong");
        detailLabel.textContent = `${line.label}: `;
        const detailValue = document.createElement("span");
        detailValue.textContent = line.value;
        detail.append(detailLabel, detailValue);
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
