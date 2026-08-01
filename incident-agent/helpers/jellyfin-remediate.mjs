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

async function requestBuffer(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`local_api_${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

async function requestText(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`local_api_${response.status}`);
  return response.text();
}

function databaseScalar(statement) {
  const result = spawnSync("/usr/bin/sqlite3", [jellyfinDatabase, statement], { encoding: "utf8", timeout: 10000 });
  if (result.status !== 0) throw new Error("jellyfin_database_unavailable");
  return result.stdout.trim();
}

function jellyfinToken() {
  const token = databaseScalar("select AccessToken from ApiKeys order by DateLastActivity desc limit 1;");
  if (!token) throw new Error("jellyfin_token_unavailable");
  return token;
}

function databaseId(apiId) {
  if (!/^[0-9a-f]{32}$/iu.test(apiId)) throw new Error("invalid_jellyfin_item");
  return `${apiId.slice(0, 8)}-${apiId.slice(8, 12)}-${apiId.slice(12, 16)}-${apiId.slice(16, 20)}-${apiId.slice(20)}`.toUpperCase();
}

function lastRefresh(apiId) {
  const id = databaseId(apiId);
  return databaseScalar(`select coalesce(DateLastRefreshed, '') from BaseItems where Id='${id}';`);
}

function imageMetrics(buffer) {
  const dimensions = spawnSync("/usr/bin/magick", ["identify", "-format", "%w %h", "-"], {
    input: buffer,
    encoding: "utf8",
    timeout: 30000,
    maxBuffer: 1024 * 1024
  });
  const [width, height] = dimensions.stdout.trim().split(/\s+/u).map(Number);
  if (dimensions.status !== 0 || !width || !height) throw new Error("jellyfin_image_decode_failed");
  const sharpnessResult = spawnSync("/usr/bin/magick", [
    "-", "-resize", "512x512>", "-colorspace", "Gray", "-morphology", "Convolve", "Laplacian:0",
    "-format", "%[fx:standard_deviation]", "info:"
  ], { input: buffer, encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
  const sharpness = Number(sharpnessResult.stdout.trim());
  if (sharpnessResult.status !== 0 || !Number.isFinite(sharpness)) throw new Error("jellyfin_image_analysis_failed");
  return { width, height, sharpness: Number(sharpness.toFixed(4)) };
}

async function exactSeries(series, headers) {
  const query = new URLSearchParams({
    Recursive: "true",
    SearchTerm: series,
    IncludeItemTypes: "Series",
    Limit: "20"
  });
  const result = await requestJson(`${jellyfinOrigin}/Items?${query}`, { headers });
  const wanted = normalize(series);
  return result?.Items?.find((candidate) => normalize(candidate.Name) === wanted) ?? null;
}

async function refreshJellyfinImages(series) {
  const token = jellyfinToken();
  const headers = { "x-emby-token": token };
  let endpoint = "/Library/Refresh";
  let target = "library";
  let item = null;
  let previousRefresh = "";
  if (series) {
    item = await exactSeries(series, headers);
    if (!item?.Id) throw new Error("jellyfin_item_not_found");
    previousRefresh = lastRefresh(item.Id);
    const refresh = new URLSearchParams({
      Recursive: "true",
      MetadataRefreshMode: "FullRefresh",
      ImageRefreshMode: "FullRefresh",
      ReplaceAllMetadata: "false",
      ReplaceAllImages: "true"
    });
    endpoint = `/Items/${encodeURIComponent(item.Id)}/Refresh?${refresh}`;
    target = "series";
  }
  await requestJson(`${jellyfinOrigin}${endpoint}`, { method: "POST", headers });
  if (!item) return { ok: true, action: "refresh_jellyfin_images", accepted: true, verified: false, target };

  let refreshed = false;
  for (let attempt = 0; attempt < 90; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const currentRefresh = lastRefresh(item.Id);
    if (currentRefresh && currentRefresh !== previousRefresh) {
      refreshed = true;
      break;
    }
  }
  if (!refreshed) throw new Error("jellyfin_refresh_timeout");

  item = await exactSeries(series, headers);
  const tag = item?.ImageTags?.Primary;
  if (!tag) throw new Error("jellyfin_image_not_verified");
  const primary = imageMetrics(await requestBuffer(`${jellyfinOrigin}/Items/${item.Id}/Images/Primary?quality=100&tag=${encodeURIComponent(tag)}`, { headers }));
  const backdrop = imageMetrics(await requestBuffer(`${jellyfinOrigin}/Items/${item.Id}/Images/Backdrop/0?quality=100`, { headers }));
  const brandingText = await requestText(`${jellyfinOrigin}/Branding/Css`);
  const displayBlurDisabled = brandingText.includes("Keep title backdrops sharp")
    && /body:has\(#itemDetailPage\) \.backdropImage[\s\S]{0,300}filter:\s*saturate\(/u.test(brandingText);
  const verified = primary.width >= 600 && primary.height >= 900 && primary.sharpness >= 0.08
    && backdrop.width >= 1280 && backdrop.height >= 720 && backdrop.sharpness >= 0.08
    && displayBlurDisabled;
  if (!verified) throw new Error("jellyfin_image_not_verified");
  return {
    ok: true,
    action: "refresh_jellyfin_images",
    accepted: true,
    verified,
    target,
    primary,
    backdrop,
    displayBlurDisabled
  };
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
