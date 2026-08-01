const JELLYFIN_ACTIONS = {
  availability: ["no_action", "restart_origin", "reload_proxy"],
  performance: ["no_action", "restart_origin", "reload_proxy"],
  playback: ["no_action", "restart_origin"],
  images: ["no_action", "refresh_jellyfin_images"],
  anime_download: ["no_action", "requeue_hianime"]
};

const NO_ACTION_TEXT = {
  unsupported_application: "Keine automatische Reparatur ausgeführt: Automatische Bug-Reparaturen sind auf Jellyfin begrenzt.",
  unsupported_category: "Keine automatische Reparatur ausgeführt: Die Meldung gehört keiner freigegebenen Jellyfin-Fehlerklasse an.",
  missing_series: "Keine automatische Reparatur ausgeführt: Für die gezielte Jellyfin-Reparatur fehlt der Serienname.",
  insufficient_evidence: "Keine automatische Reparatur ausgeführt: Die technische Prüfung rechtfertigt keinen sicheren Eingriff."
};

const SUCCESS_TEXT = {
  restart_origin: "Jellyfin wurde neu gestartet und anschließend erfolgreich geprüft.",
  reload_proxy: "Der Jellyfin-Proxy wurde neu geladen und anschließend erfolgreich geprüft.",
  refresh_jellyfin_images: "Jellyfin hat die Bilder neu geladen; Aktualisierungsabschluss, Auflösung, Bildschärfe und die tatsächliche Darstellung wurden anschließend geprüft.",
  requeue_hianime: "Der passende fehlgeschlagene HiAnime-Download wurde erneut eingereiht."
};

const FAILURE_TEXT = {
  action_failed: "Die freigegebene Reparatur konnte technisch nicht ausgeführt werden.",
  hianime_match_not_found: "Es wurde kein eindeutig passender fehlgeschlagener HiAnime-Download gefunden.",
  jellyfin_item_not_found: "Die angegebene Serie wurde in Jellyfin nicht eindeutig gefunden.",
  jellyfin_refresh_timeout: "Jellyfin hat die Bildaktualisierung nicht innerhalb des Prüffensters abgeschlossen.",
  jellyfin_image_not_verified: "Das erneuerte Jellyfin-Bild bestand die Auflösungs-, Schärfe- oder Darstellungsprüfung nicht.",
  recovery_not_verified: "Die Reparatur wurde ausgeführt, aber die anschließende Prüfung war nicht erfolgreich.",
  helper_failed: "Der lokale Jellyfin-Reparaturdienst hat die Aktion abgelehnt."
};

export function allowedActionsFor(app, category, hasSeries) {
  if (app.slug !== "jellyfin") return ["no_action"];
  const configured = new Set(app.allowedActions ?? []);
  const candidates = JELLYFIN_ACTIONS[category] ?? ["no_action"];
  const scoped = candidates.filter((action) => action === "no_action" || configured.has(action));
  if ((category === "images" || category === "anime_download") && !hasSeries) return ["no_action"];
  return scoped.includes("no_action") ? scoped : ["no_action", ...scoped];
}

export function noActionReasonFor(app, category, hasSeries) {
  if (app.slug !== "jellyfin") return "unsupported_application";
  if ((category === "images" || category === "anime_download") && !hasSeries) return "missing_series";
  if (!Object.hasOwn(JELLYFIN_ACTIONS, category)) return "unsupported_category";
  return "insufficient_evidence";
}

export function outcomeComment({ action, incidentId, noActionReason, failureCode }) {
  const marker = `<!-- fasrv-agent-outcome:v2:${incidentId} -->`;
  if (failureCode) {
    const reason = FAILURE_TEXT[failureCode] ?? FAILURE_TEXT.helper_failed;
    return `${reason}\nDer Vorgang bleibt für eine manuelle Prüfung offen.\n\nChecked by: Grok 4.5\n${marker}`;
  }
  if (action === "no_action") {
    const reason = NO_ACTION_TEXT[noActionReason] ?? NO_ACTION_TEXT.insufficient_evidence;
    return `${reason}\nDer Vorgang bleibt für eine manuelle Prüfung offen.\n\nChecked by: Grok 4.5\n${marker}`;
  }
  const result = SUCCESS_TEXT[action];
  if (!result) throw new Error("unknown_outcome_action");
  return `${result}\n\nSolved by: Grok 4.5\n${marker}`;
}

export function outcomeMarker(incidentId) {
  return `<!-- fasrv-agent-outcome:v2:${incidentId} -->`;
}

export function isSecurityInterruption(code) {
  return code === "security_gate" || code === "pipeline_paused";
}
