import test from "node:test";
import assert from "node:assert/strict";
import { allowedActionsFor, isSecurityInterruption, noActionReasonFor, outcomeComment } from "../lib/remediation.mjs";
import { normalize, titleMatches } from "../helpers/jellyfin-remediate.mjs";
import { detectPromptInjection, SecretScanner } from "../lib/security.mjs";

const jellyfin = {
  slug: "jellyfin",
  allowedActions: ["no_action", "restart_origin", "reload_proxy", "refresh_jellyfin_images", "requeue_hianime"]
};

test("limits automated bug repair to Jellyfin categories", () => {
  assert.deepEqual(allowedActionsFor({ slug: "home-assistant", allowedActions: ["restart_origin"] }, "availability", true), ["no_action", "restart_origin"]);
  assert.deepEqual(allowedActionsFor({ slug: "home-assistant", allowedActions: ["restart_origin"] }, "images", true), ["no_action"]);
  assert.deepEqual(allowedActionsFor(jellyfin, "playback", false), ["no_action", "restart_origin"]);
  assert.deepEqual(allowedActionsFor(jellyfin, "images", true), ["no_action", "refresh_jellyfin_images"]);
  assert.deepEqual(allowedActionsFor(jellyfin, "images", false), ["no_action"]);
  assert.deepEqual(allowedActionsFor(jellyfin, "anime_download", true), ["no_action", "requeue_hianime"]);
  assert.deepEqual(allowedActionsFor(jellyfin, "anime_download", false), ["no_action"]);
  assert.deepEqual(allowedActionsFor(jellyfin, "login", false), ["no_action"]);
});

test("uses fixed non-public explanations for every outcome", () => {
  assert.equal(noActionReasonFor({ slug: "home-assistant" }, "availability", false), "insufficient_evidence");
  assert.equal(noActionReasonFor(jellyfin, "images", false), "missing_series");
  assert.equal(noActionReasonFor(jellyfin, "anime_download", false), "missing_series");
  assert.match(outcomeComment({ action: "no_action", incidentId: "test-1", noActionReason: "missing_series" }), /Checked by: Grok 4\.5/u);
  assert.match(outcomeComment({ action: "requeue_hianime", incidentId: "test-2" }), /Solved by: Grok 4\.5/u);
  assert.match(outcomeComment({ action: "restart_origin", incidentId: "test-3", failureCode: "recovery_not_verified" }), /manuelle Prüfung/u);

  const comments = [
    ...["restart_origin", "reload_proxy", "refresh_jellyfin_images", "requeue_hianime"].map((action) => outcomeComment({ action, incidentId: `success-${action}` })),
    ...["unsupported_application", "unsupported_category", "missing_series", "insufficient_evidence"].map((noActionReason) => outcomeComment({ action: "no_action", incidentId: `skip-${noActionReason}`, noActionReason })),
    ...["action_failed", "helper_failed", "hianime_match_not_found", "jellyfin_item_not_found", "jellyfin_refresh_timeout", "jellyfin_image_not_verified", "recovery_not_verified"].map((failureCode) => outcomeComment({ action: "no_action", incidentId: `failure-${failureCode}`, failureCode }))
  ];
  const scanner = new SecretScanner();
  for (const comment of comments) {
    assert.equal(detectPromptInjection(comment), null);
    assert.equal(scanner.scan(comment), null);
  }
});

test("distinguishes security interruptions from repair failures", () => {
  assert.equal(isSecurityInterruption("security_gate"), true);
  assert.equal(isSecurityInterruption("pipeline_paused"), true);
  assert.equal(isSecurityInterruption("action_failed"), false);
});

test("matches HiAnime logs conservatively by validated series title", () => {
  const log = "[web] Link: https://hianime.example/watch/example-show-1234\nYou have chosen Example Show\n";
  assert.equal(normalize("Example--Show"), "example show");
  assert.equal(titleMatches("Example Show", log), true);
  assert.equal(titleMatches("Different Show", log), false);
});
