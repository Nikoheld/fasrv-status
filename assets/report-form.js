(() => {
  "use strict";

  function boot() {
  const API = "https://share.fasrv.ch/status-report-api";
  const applications = [
    ["fasrv-dashboard", "FASRV Dashboard"],
    ["home-assistant", "Home Assistant"],
    ["jellyfin", "Jellyfin"],
    ["jellyseerr", "Jellyseerr"],
    ["immich", "Immich"],
    ["share", "Share"],
    ["file-tools", "File Tools"],
    ["software", "Software"],
    ["codex-web", "Codex Web"],
    ["kavita", "Kavita"],
    ["hi-anime-downloader", "HiAnime Downloader"],
    ["uptime-kuma", "Uptime Kuma"],
    ["fahoot", "Fahoot"],
    ["fabio-hub", "FabioHub"],
    ["red-alpine", "RedAlpine"],
    ["bg-fabio-and-simon", "BG Fabio and Simon"],
    ["animation-fabio", "Animation Fabio"]
  ];

  function element(name, attributes = {}, text = "") {
    const node = document.createElement(name);
    for (const [key, value] of Object.entries(attributes)) {
      if (key === "className") node.className = value;
      else node.setAttribute(key, value);
    }
    if (text) node.textContent = text;
    return node;
  }

  async function sha256(value) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function solve(challenge) {
    const prefix = "0".repeat(challenge.difficulty);
    for (let counter = 0; counter < 2000000; counter += 1) {
      if ((await sha256(`${challenge.nonce}:${counter}`)).startsWith(prefix)) return { id: challenge.id, counter };
      if (counter % 250 === 0) await new Promise((resolve) => setTimeout(resolve, 0));
    }
    throw new Error("challenge_failed");
  }

  const root = document.getElementById("fasrv-report-root");
  if (!root) return;

  const section = element("section", { className: "fasrv-report", "aria-labelledby": "fasrv-report-title" });
  const inner = element("div", { className: "fasrv-report__inner" });
  const heading = element("div", { className: "fasrv-report__heading" });
  heading.append(element("h2", { id: "fasrv-report-title" }, "Störung melden"));
  heading.append(element("p", {}, "Probleme direkt an die technische Prüfung senden."));

  const form = element("form", { className: "fasrv-report__form" });
  const appField = element("label", { className: "fasrv-report__field" });
  appField.append(element("span", {}, "Anwendung"));
  const appSelect = element("select", { name: "app", required: "" });
  appSelect.append(element("option", { value: "", disabled: "", selected: "" }, "Anwendung auswählen"));
  for (const [value, label] of applications) appSelect.append(element("option", { value }, label));
  appField.append(appSelect);

  const descriptionField = element("label", { className: "fasrv-report__field" });
  descriptionField.append(element("span", {}, "Problem"));
  const description = element("textarea", { name: "description", rows: "3", minlength: "8", maxlength: "500", required: "", placeholder: "Kurz beschreiben, was nicht funktioniert" });
  descriptionField.append(description);

  const seriesField = element("label", { className: "fasrv-report__field", hidden: "" });
  seriesField.append(element("span", {}, "Serie (optional)"));
  const series = element("input", { name: "series", type: "text", maxlength: "120", autocomplete: "off", placeholder: "Name der Serie" });
  seriesField.append(series);

  const honeypot = element("input", { className: "fasrv-report__website", name: "website", type: "text", tabindex: "-1", autocomplete: "off", "aria-hidden": "true" });
  const footer = element("div", { className: "fasrv-report__footer" });
  const status = element("p", { className: "fasrv-report__status", role: "status", "aria-live": "polite" });
  const submit = element("button", { type: "submit" }, "Meldung senden");
  footer.append(status, submit);
  form.append(appField, descriptionField, seriesField, honeypot, footer);
  inner.append(heading, form);
  section.append(inner);
  root.append(section);
  document.querySelector("#sapper > footer")?.before(root);

  appSelect.addEventListener("change", () => {
    const jellyfin = appSelect.value === "jellyfin";
    seriesField.hidden = !jellyfin;
    if (!jellyfin) series.value = "";
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.dataset.state = "working";
    status.textContent = "Meldung wird geprüft ...";
    try {
      const challengeResponse = await fetch(`${API}/v1/challenge`, { mode: "cors", cache: "no-store" });
      if (!challengeResponse.ok) throw new Error("unavailable");
      const proof = await solve(await challengeResponse.json());
      const response = await fetch(`${API}/v1/reports`, {
        method: "POST",
        mode: "cors",
        cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ app: appSelect.value, description: description.value, series: series.value, website: honeypot.value, proof })
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error ?? "failed");
      form.reset();
      seriesField.hidden = true;
      status.dataset.state = "success";
      status.textContent = `Meldung angenommen. Referenz: ${result.reference}`;
    } catch (error) {
      status.dataset.state = "error";
      status.textContent = error.message === "rate_limited" ? "Zu viele Meldungen. Bitte später erneut versuchen." : "Meldung konnte nicht gesendet werden.";
    } finally {
      submit.disabled = false;
    }
  });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
  else boot();
})();
