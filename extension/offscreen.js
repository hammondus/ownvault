/*
 * Own Vault extension — offscreen vault host.
 *
 * Owns Vault (crypto + IndexedDB) and Sync for the whole extension. The
 * popup and content scripts hold no key material and no plaintext beyond
 * what they display or fill; they ask this document for everything via
 * chrome.runtime messages ("ov:*", answered here; "ov:ensure" is the
 * service worker's).
 *
 * Auto-lock mirrors the PWA: a fixed inactivity window, reset by any
 * message that implies the user is present. The unlocked CryptoKey never
 * leaves this document — non-extractable, same as the PWA.
 */
"use strict";

(function () {
  var AUTO_LOCK_MS = 5 * 60 * 1000;
  var CLIP_CLEAR_MS = 20 * 1000;

  var idleTimer = null;
  var clipTimer = null;

  function resetIdle() {
    clearTimeout(idleTimer);
    if (Vault.isUnlocked()) idleTimer = setTimeout(lockNow, AUTO_LOCK_MS);
  }

  function lockNow() {
    Vault.lock();
    Sync.stop();
    clearTimeout(idleTimer);
    broadcast({ type: "ov:changed", locked: true });
  }

  // Tell any open popup that state moved under it (a pulled sync, a lock).
  // Fire-and-forget: most of the time no popup is open and the message has
  // no receiver, which surfaces as a rejection to swallow.
  function broadcast(msg) {
    try {
      chrome.runtime.sendMessage(msg).catch(function () {});
    } catch (e) {
      /* ignore */
    }
  }

  Vault.onChange(function (local) {
    if (local) Sync.syncSoon();
    broadcast({ type: "ov:changed" });
  });
  Sync.onStatus(function (st) {
    broadcast({ type: "ov:sync-status", status: st });
  });

  /* ---------- entry shapes ---------- */
  // The popup list gets metadata only; passwords travel per-entry, on
  // demand, so a long-lived popup holds at most one secret at a time.

  function listItem(e) {
    return {
      id: e.id,
      title: e.title || "",
      username: e.username || "",
      url: e.url || "",
      critical: !!e.critical,
      hasTotp: !!e.totp
    };
  }

  function hostOf(url) {
    var m = /^(?:https?:\/\/)?([^\/:?#]+)/i.exec(url || "");
    return m ? m[1].toLowerCase() : "";
  }

  // Match an entry to the active tab's hostname: exact host, or the entry's
  // host is a parent domain of the tab's (login.example.com matches an entry
  // saved as example.com). Deliberately not the reverse — an entry for
  // app.example.com should not offer itself to evil.example.com's siblings
  // beyond what the suffix rule already allows.
  function matchesHost(entryUrl, tabHost) {
    var eh = hostOf(entryUrl);
    if (!eh || !tabHost) return false;
    return tabHost === eh || tabHost.slice(-(eh.length + 1)) === "." + eh;
  }

  /* ---------- message API ---------- */

  var handlers = {
    "ov:status": function () {
      return Vault.isInitialized().then(function (init) {
        return {
          initialized: init,
          unlocked: Vault.isUnlocked(),
          serverUrl: Sync.getServerUrl(),
          vaultId: Sync.getVaultId(),
          hasToken: !!Sync.getToken(),
          sync: Sync.getStatus()
        };
      });
    },

    // First-run: point at a server + vault, pull, and report what the lock
    // gate should show next. The vault id goes FIRST: config keys are
    // suffixed per vault, so serverUrl/token need an active id to land
    // under. Setting config before bootstrap is safe: a failed pull leaves
    // an empty local vault and connect can run again.
    "ov:connect": function (msg) {
      Sync.setVaultId((msg.vaultId || "").trim());
      Sync.setServerUrl(msg.serverUrl || "");
      Sync.setToken(msg.token || "");
      return Sync.bootstrap();
    },

    "ov:unlock": function (msg) {
      return Vault.unlock(msg.password).then(function () {
        resetIdle();
        Sync.start();
        return { ok: true };
      });
    },

    "ov:lock": function () {
      lockNow();
      return Promise.resolve({ ok: true });
    },

    "ov:sync": function () {
      return Sync.syncNow().then(function () {
        return Sync.getStatus();
      });
    },

    "ov:list": function () {
      resetIdle();
      return Vault.list().then(function (rows) {
        rows.sort(function (a, b) {
          return (a.title || "").localeCompare(b.title || "");
        });
        return rows.map(listItem);
      });
    },

    "ov:matches": function (msg) {
      resetIdle();
      var host = (msg.host || "").toLowerCase();
      return Vault.list().then(function (rows) {
        return rows
          .filter(function (e) {
            return matchesHost(e.url, host);
          })
          .map(listItem);
      });
    },

    // Full entry for the detail view / fill: the one message that carries a
    // password. The TOTP code is computed here so the secret itself never
    // leaves this document.
    "ov:credentials": function (msg) {
      resetIdle();
      return Vault.get(msg.id).then(function (e) {
        if (!e) throw new Error("no such entry");
        var base = listItem(e);
        base.password = e.password || "";
        base.notes = e.notes || "";
        // Custom fields ride the credentials message, never the list one:
        // they can hold secrets, and listItem() is sent for every entry in
        // the vault at once.
        base.fields = e.fields || [];
        if (!e.totp) return base;
        return Totp.code(e.totp, Date.now()).then(function (r) {
          base.totp = r;
          return base;
        });
      });
    },

    "ov:totp": function (msg) {
      resetIdle();
      return Vault.get(msg.id).then(function (e) {
        if (!e || !e.totp) throw new Error("no code");
        return Totp.code(e.totp, Date.now());
      });
    },

    // Clipboard hygiene: the popup copies, then dies when it loses focus —
    // its own wipe timer would die with it. This document outlives it, and
    // the offscreen clipboard API (execCommand on a focused textarea) works
    // without window focus.
    "ov:clip-wipe": function () {
      clearTimeout(clipTimer);
      clipTimer = setTimeout(function () {
        var ta = document.createElement("textarea");
        ta.value = " ";
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
        } catch (e) {
          /* best effort */
        }
        ta.remove();
      }, CLIP_CLEAR_MS);
      return Promise.resolve({ ok: true });
    }
  };

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    var h = msg && handlers[msg.type];
    if (!h) return false;
    h(msg).then(
      function (result) {
        sendResponse({ ok: true, data: result });
      },
      function (err) {
        sendResponse({ ok: false, error: (err && err.message) || String(err) });
      }
    );
    return true; // async sendResponse
  });
})();
