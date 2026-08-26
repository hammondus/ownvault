/*
 * Own Vault extension — MV3 service worker.
 *
 * Deliberately tiny: its one job is keeping the offscreen document alive.
 * All vault state lives in the offscreen document (offscreen.js), because a
 * service worker is killed after ~30s idle and the unlocked vault key — a
 * non-extractable CryptoKey — can only live in the memory of a page that
 * stays up. The popup and content scripts message the offscreen document
 * directly (chrome.runtime messages reach every extension context); the only
 * message answered HERE is "ov:ensure", which guarantees that document
 * exists before anyone talks to it.
 */
"use strict";

var creating = null; // dedupe concurrent createDocument calls

function ensureOffscreen() {
  return chrome.offscreen.hasDocument().then(function (has) {
    if (has) return;
    if (!creating) {
      creating = chrome.offscreen
        .createDocument({
          url: "offscreen.html",
          reasons: ["LOCAL_STORAGE", "WORKERS"],
          justification:
            "Holds the unlocked vault key in memory and runs crypto, storage, and sync; a service worker is evicted too aggressively to hold session state."
        })
        .catch(function (e) {
          // A concurrent create from another event can race hasDocument();
          // "already exists" is success.
          if (!/exists/i.test(String(e && e.message))) throw e;
        })
        .then(function () {
          creating = null;
        });
    }
    return creating;
  });
}

chrome.runtime.onInstalled.addListener(function () {
  ensureOffscreen();
});
chrome.runtime.onStartup.addListener(function () {
  ensureOffscreen();
});

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || msg.type !== "ov:ensure") return false; // offscreen.js handles the rest
  ensureOffscreen().then(
    function () {
      sendResponse({ ok: true });
    },
    function (e) {
      sendResponse({ ok: false, error: String(e && e.message) });
    }
  );
  return true; // async sendResponse
});
