#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const jellyfinOrigin = "http://127.0.0.1:8096";
const hianimeOrigin = "http://127.0.0.1:8100";
const jellyfinDatabase = "/opt/docker-config/jellyfin/data/data/jellyfin.db";

export function normalize(value) {
  return String(value ?? "")
    .normalize("NFKC")
    .toLocaleLowerCase("de-CH")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .replace(/\s+/gu, " ");
}

function validateSeries(value, required) {
  const series = String(value ?? "").normalize("NFKC").trim();
  if (!series && !required) return "";
  if (!series || series.length > 120 || !/^[\p{L}\p{N}\p{M}\s.:'\-&]+$/u.test(series)) throw new Error("invalid_series");
  return series;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(15000) });
  const text = await response.text();
  if (!response.ok) throw new Error(`local_api_${response.status}`);
  return text ? JSON.parse(text) : null;
}

function jellyfinToken() {
  const result = spawnSync("/usr/bin/sqlite3", [
    jellyfinDatabase,
    "select AccessToken from ApiKeys order by DateLastActivity desc limit 1;"
  ], { encoding: "utf8", timeout: 10000 });
  const token = result.stdout.trim();
  if (result.status !== 0 || !token) throw new Error("jellyfin_token_unavailable");
  return token;
}

async function refreshJellyfinImages(series) {
  const token = jellyfinToken();
  const headers = { "x-emby-token": token };
  let endpoint = "/Library/Refresh";
  let target = "library";
  if (series) {
    const query = new URLSearchParams({
      Recursive: "true",
      SearchTerm: series,
      IncludeItemTypes: "Series",
      Limit: "20"
    });
    const result = await requestJson(`${jellyfinOrigin}/Items?${query}`, { headers });
    const wanted = normalize(series);
    const item = result?.Items?.find((candidate) => normalize(candidate.Name) === wanted);
    if (!item?.Id) throw new Error("jellyfin_item_not_found");
    const refresh = new URLSearchParams({
      Recursive: "true",
      MetadataRefreshMode: "FullRefresh",
      ImageRefreshMode: "FullRefresh",
      ReplaceAllMetadata: "false",
      ReplaceAllImages: "false"
    });
    endpoint = `/Items/${encodeURIComponent(item.Id)}/Refresh?${refresh}`;
    target = "series";
  }
  await requestJson(`${jellyfinOrigin}${endpoint}`, { method: "POST", headers });
  return { ok: true, action: "refresh_jellyfin_images", accepted: true, target };
}

function candidateNames(content) {
  const names = [];
  const chosen = content.match(/^\s*You have chosen\s+(.+?)\s*$/imu)?.[1];
  if (chosen) names.push(chosen);
  const link = content.match(/^\[web\] Link:\s*(\S+)\s*$/imu)?.[1];
  if (link) {
    try {
      const slug = new URL(link).pathname.split("/").filter(Boolean).at(-1) ?? "";
      names.push(slug.replace(/-\d+$/u, "").replace(/[-_]+/gu, " "));
    } catch { /* invalid historic link is ignored */ }
  }
  return names.map(normalize).filter(Boolean);
}

export function titleMatches(series, content) {
  const wanted = normalize(series);
  return candidateNames(content).some((candidate) => (
    candidate === wanted || candidate.startsWith(`${wanted} `) || wanted.startsWith(`${candidate} `)
  ));
}

async function requeueHianime(series) {
  const listing = await requestJson(`${hianimeOrigin}/api/logs`);
  const failed = (listing?.logs ?? []).filter((log) => /^(?:Fehler:|Teilweise erfolgreich:)/u.test(log.summary ?? ""));
  for (const log of failed.slice(0, 100)) {
    if (!/^[0-9A-Za-z._-]+\.log$/u.test(log.name ?? "")) continue;
    const detail = await requestJson(`${hianimeOrigin}/api/logs/${encodeURIComponent(log.name)}`);
    if (!detail?.ok || !titleMatches(series, detail.content ?? "")) continue;
    const result = await requestJson(`${hianimeOrigin}/api/logs/${encodeURIComponent(log.name)}/requeue`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}"
    });
    if (!result?.ok || !result.job?.id) throw new Error("hianime_requeue_rejected");
    return { ok: true, action: "requeue_hianime", accepted: true, target: "failed_job" };
  }
  throw new Error("hianime_match_not_found");
}

async function main() {
  const [action, rawSeries = ""] = process.argv.slice(2);
  if (action === "refresh-images") return refreshJellyfinImages(validateSeries(rawSeries, false));
  if (action === "requeue-hianime") return requeueHianime(validateSeries(rawSeries, true));
  throw new Error("action_not_allowed");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(JSON.stringify(await main()));
  } catch (error) {
    console.log(JSON.stringify({ ok: false, code: error.message }));
    process.exitCode = 1;
  }
}
