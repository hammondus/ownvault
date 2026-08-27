/*
 * Own Vault — sync engine.
 *
 * Orchestrates multi-device sync against the Go server over same-origin HTTP.
 * It speaks only JSON: all crypto and binary handling stays in vault.js, and
 * the server only ever sees ciphertext + server-assigned revs.
 *
 * Flow (syncNow): pull everything past our cursor and merge (silent unless an
 * entry we edited locally also moved on the server -> conflict), then push our
 * pending meta + dirty entries with optimistic concurrency. An SSE "changed"
 * notification from another device triggers a debounced re-sync.
 *
 * Config (localStorage, not secret-bearing beyond the shared token):
 *   syncEnabled ("0" disables), syncToken (bearer token for public servers),
 *   vaultId (which namespace on the server this device's vault lives in),
 *   serverUrl (base URL of the sync server; empty = same origin — the PWA
 *   case. The browser extension sets it, since its pages live on a
 *   chrome-extension:// origin and every call must name the server).
 *
 * The vault id is the multi-tenant key: one server can hold many unrelated
 * people's vaults, each under its own random id, and the server only ever sees
 * that opaque id plus ciphertext. A new device joins an existing vault by being
 * given its id (the connect step in vaultui.js); creating a vault mints a fresh
 * one. It is sent as X-Vault-Id on every /api/* call.
 */
window.Sync = (function () {
  "use strict";

  var ENABLED_KEY = "syncEnabled";
  var TOKEN_KEY = "syncToken";
  var VAULT_KEY = "vaultId";
  var SERVER_KEY = "serverUrl";
  var DEBOUNCE_MS = 600;

  var listeners = [];
  var lastStatus = { state: "idle", ok: true, message: "", conflicts: 0 };
  var syncing = false;
  var queued = false;
  var events = null;
  var debounceTimer = null;

  /* ---------- config ---------- */

  function isEnabled() {
    try {
      return localStorage.getItem(ENABLED_KEY) !== "0";
    } catch (e) {
      return true;
    }
  }

  function setEnabled(on) {
    try {
      localStorage.setItem(ENABLED_KEY, on ? "1" : "0");
    } catch (e) {
      /* ignore */
    }
    if (on) {
      subscribe();
      syncSoon();
    } else {
      unsubscribe();
    }
  }

  function getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function setToken(t) {
    try {
      localStorage.setItem(TOKEN_KEY, t || "");
    } catch (e) {
      /* ignore */
    }
  }

  function getServerUrl() {
    try {
      // Normalized without a trailing slash so paths concatenate cleanly.
      return (localStorage.getItem(SERVER_KEY) || "").replace(/\/+$/, "");
    } catch (e) {
      return "";
    }
  }

  function setServerUrl(u) {
    try {
      localStorage.setItem(SERVER_KEY, (u || "").trim().replace(/\/+$/, ""));
    } catch (e) {
      /* ignore */
    }
  }

  function getVaultId() {
    try {
      return localStorage.getItem(VAULT_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function setVaultId(id) {
    try {
      localStorage.setItem(VAULT_KEY, id || "");
    } catch (e) {
      /* ignore */
    }
  }

  // A fresh random namespace for a brand-new vault. UUID where available (easy
  // to read out to another device), random hex otherwise.
  function newVaultId() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
    var b = window.crypto.getRandomValues(new Uint8Array(16));
    var s = "";
    for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
    return s;
  }

  // Guarantee this device has a vault id (used the moment a local vault exists
  // so sync has a namespace to push into). Never overwrites an existing one.
  function ensureVaultId() {
    var id = getVaultId();
    if (!id) {
      id = newVaultId();
      setVaultId(id);
    }
    return id;
  }

  /* ---------- status ---------- */

  function onStatus(cb) {
    listeners.push(cb);
  }

  function emit(status) {
    lastStatus = status;
    listeners.forEach(function (cb) {
      try {
        cb(status);
      } catch (e) {
        /* ignore */
      }
    });
  }

  function getStatus() {
    return lastStatus;
  }

  /* ---------- HTTP ---------- */

  function headers(extra) {
    var h = extra || {};
    var t = getToken();
    if (t) h["X-Vault-Token"] = t;
    var v = getVaultId();
    if (v) h["X-Vault-Id"] = v;
    // Per-vault write credential, derived from the vault key on unlock
    // (vault.js). The server requires it on writes; harmless on reads. A
    // caller-set value wins: the rotating meta push must present the OLD
    // credential here (with the new one in X-Vault-Write-New).
    var wa = window.Vault && Vault.getWriteAuth ? Vault.getWriteAuth() : "";
    if (wa && !h["X-Vault-Write"]) h["X-Vault-Write"] = wa;
    return h;
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = headers(opts.headers);
    return fetch(getServerUrl() + path, opts);
  }

  function pull() {
    return api("/api/pull?since=" + Vault.getCursor())
      .then(function (res) {
        if (res.status === 401) throw { auth: true };
        if (!res.ok) throw new Error("pull " + res.status);
        return res.json();
      })
      .then(function (data) {
        // A bad wrapped-key record (hostile co-tenant, corruption) must not
        // take entry syncing down with it: applyMeta rejects it (docToMeta
        // enforces the KDF bounds) and we carry on — the good local record
        // still unlocks the vault. Promise.resolve().then() also routes
        // applyMeta's synchronous throw into this catch.
        var metaP = data.meta
          ? Promise.resolve()
              .then(function () {
                return Vault.applyMeta(data.meta.doc, data.meta.rev);
              })
              .catch(function (err) {
                if (window.console) console.warn("ignoring bad server meta:", err);
              })
          : Promise.resolve();
        return metaP
          .then(function () {
            return Vault.applyPulled(data.entries);
          })
          .then(function () {
            Vault.setCursor(data.rev);
          });
      });
  }

  function push() {
    // Writes need the per-vault credential, which only exists while unlocked.
    // A debounced sync can fire just after a lock; skip the push half — the
    // dirty flags survive, and the next unlocked sync pushes them.
    if (!Vault.getWriteAuth()) return Promise.resolve();
    return Vault.pendingMeta()
      .then(function (metaDoc) {
        if (!metaDoc) return;
        return Vault.getPendingRotation().then(function (rot) {
          var h = { "Content-Type": "application/json" };
          if (rot) {
            // Full re-encrypt replaced the vault key: prove the old
            // credential and hand the server the new one in the same write
            // that installs the new wrapped-key record.
            h["X-Vault-Write"] = rot;
            h["X-Vault-Write-New"] = Vault.getWriteAuth();
          }
          return api("/api/meta", {
            method: "PUT",
            headers: h,
            body: JSON.stringify({ doc: metaDoc })
          });
        })
          .then(function (res) {
            if (res.status === 401) throw { auth: true };
            if (res.status === 403) throw { writeAuth: true };
            if (!res.ok) throw new Error("meta " + res.status);
            return res.json();
          })
          .then(function (r) {
            return Vault.confirmMetaPushed(r.rev);
          });
      })
      .then(function () {
        return Vault.pendingPush();
      })
      .then(pushInBatches);
  }

  // The server caps /api/push bodies (8MB) so one tenant can't fill a shared
  // server's RAM, but a full-vault restore marks *every* entry dirty at once —
  // a single unchunked POST of a big vault would exceed the cap on every
  // retry, wedging sync permanently. So split pushes well below the cap; each
  // batch is confirmed (revs recorded) before the next is sent, so an
  // interruption just leaves the remainder dirty for the next sync.
  var PUSH_BATCH_BYTES = 2 * 1024 * 1024;

  function pushInBatches(items) {
    if (!items.length) return;
    var batches = [];
    var cur = [];
    var curBytes = 0;
    items.forEach(function (it) {
      var n = JSON.stringify(it).length + 1;
      if (cur.length && curBytes + n > PUSH_BATCH_BYTES) {
        batches.push(cur);
        cur = [];
        curBytes = 0;
      }
      cur.push(it);
      curBytes += n;
    });
    if (cur.length) batches.push(cur);
    return batches.reduce(function (p, batch) {
      return p.then(function () {
        return api("/api/push", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ entries: batch })
        })
          .then(function (res) {
            if (res.status === 401) throw { auth: true };
            if (res.status === 403) throw { writeAuth: true };
            if (!res.ok) throw new Error("push " + res.status);
            return res.json();
          })
          .then(function (data) {
            return Vault.confirmPushed(data.results);
          });
      });
    }, Promise.resolve());
  }

  // Full sync cycle. Never rejects: offline is a normal state, surfaced via
  // status rather than an error.
  function syncNow() {
    if (!isEnabled()) return Promise.resolve();
    // No namespace yet means nothing to sync against. A local vault always has
    // one by the time it's unlocked (start() calls ensureVaultId), so this only
    // skips the pre-vault gate states.
    if (!getVaultId()) {
      emit({ state: "idle", ok: true, message: "Sync not set up", conflicts: lastStatus.conflicts });
      return Promise.resolve();
    }
    if (syncing) {
      queued = true;
      return Promise.resolve();
    }
    syncing = true;
    emit({ state: "syncing", ok: true, message: "Syncing…", conflicts: lastStatus.conflicts });
    return pull()
      .then(push)
      .then(function () {
        return Vault.conflictCount();
      })
      .then(function (n) {
        syncing = false;
        emit({
          state: "idle",
          ok: true,
          message: n ? n + " conflict" + (n > 1 ? "s" : "") + " to resolve" : "Synced",
          conflicts: n
        });
        if (queued) {
          queued = false;
          return syncNow();
        }
      })
      .catch(function (err) {
        syncing = false;
        if (err && err.auth) {
          emit({ state: "error", ok: false, message: "Sync auth failed — check token", conflicts: lastStatus.conflicts });
        } else if (err && err.writeAuth) {
          // Another vault (different master password/key) already claimed
          // this Vault ID on the server, or the vault was re-encrypted
          // elsewhere and this device hasn't picked up the new key yet.
          emit({ state: "error", ok: false, message: "Server refused this vault's write credential", conflicts: lastStatus.conflicts });
        } else {
          emit({ state: "offline", ok: false, message: "Sync unavailable", conflicts: lastStatus.conflicts });
        }
      });
  }

  // Fresh-device bootstrap: pull meta + entries before there is a local vault,
  // so the lock gate can offer "unlock" instead of "create". Resolves to
  // { exists, needsAuth }:
  //   exists    - a vault is now present locally (meta pulled, or already here)
  //   needsAuth - the server refused for lack of a valid token, so the lock
  //               gate should prompt for one before deciding create vs unlock
  function bootstrap() {
    if (!isEnabled()) {
      return Vault.isInitialized().then(function (ex) {
        return { exists: ex, needsAuth: false };
      });
    }
    return pull().then(
      function () {
        return Vault.isInitialized().then(function (ex) {
          return { exists: ex, needsAuth: false };
        });
      },
      function (err) {
        var auth = !!(err && err.auth);
        return Vault.isInitialized().then(function (ex) {
          return { exists: ex, needsAuth: auth && !ex };
        });
      }
    );
  }

  /* ---------- setup code ---------- */

  // One-paste device setup: "ov1." + b64url(vaultId) + "." + b64url(token) +
  // "." + b64url(server origin). Parts are base64url-encoded because the
  // token is admin-chosen and could contain the separator. Every value in it
  // is already known to the server (which is also why the server may safely
  // QR-render it); the master password is deliberately absent — it never
  // travels. The origin part lets the connect screen reject a code pasted
  // into the wrong server's app, and gives the browser extension (which isn't
  // same-origin) the server URL it needs.

  function b64urlEncode(s) {
    return window
      .btoa(window.unescape(encodeURIComponent(s)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  function b64urlDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return decodeURIComponent(window.escape(window.atob(s)));
  }

  function makeSetupCode() {
    var origin =
      getServerUrl() || (window.location && window.location.origin) || "";
    return (
      "ov1." +
      b64urlEncode(getVaultId()) +
      "." +
      b64urlEncode(getToken()) +
      "." +
      b64urlEncode(origin)
    );
  }

  // {vaultId, token, url}, or null when str isn't a setup code (callers fall
  // back to treating it as a bare Vault ID).
  function parseSetupCode(str) {
    str = (str || "").trim();
    if (str.slice(0, 4) !== "ov1.") return null;
    var parts = str.slice(4).split(".");
    if (parts.length !== 3) return null;
    try {
      var vid = b64urlDecode(parts[0]);
      if (!vid) return null;
      return {
        vaultId: vid,
        token: b64urlDecode(parts[1]),
        url: b64urlDecode(parts[2])
      };
    } catch (e) {
      return null;
    }
  }

  // The setup code as a QR PNG, rendered by the server (see makeSetupCode for
  // why that's safe). POST, never GET: the code holds the token, and URLs
  // land in access logs. Resolves to a Blob for an object URL.
  function fetchSetupQR() {
    return api("/api/setupqr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: makeSetupCode() })
    }).then(function (res) {
      if (!res.ok) throw new Error("qr " + res.status);
      return res.blob();
    });
  }

  // Lock-gate auth probe: does the server accept the current token? Hits
  // /api/state (the server's purpose-built light probe). Resolves
  // { needsAuth, offline } and never rejects; the caller decides what each
  // outcome means (the create gate blocks on both — a synced vault must not
  // be created against a server that refused the token or didn't answer).
  function checkAuth() {
    return api("/api/state").then(
      function (res) {
        return { needsAuth: res.status === 401, offline: false };
      },
      function () {
        return { needsAuth: false, offline: true };
      }
    );
  }

  function syncSoon() {
    if (!isEnabled()) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(syncNow, DEBOUNCE_MS);
  }

  /* ---------- SSE: react to other devices ---------- */

  var sseRetryTimer = null;
  var sseRetryMs = 5000;

  function subscribe() {
    if (events || !isEnabled()) return;
    clearTimeout(sseRetryTimer);
    try {
      // Scope change notifications to our vault so a shared server doesn't wake
      // us for other people's writes. (app.js keeps a separate, unscoped
      // EventSource purely for reachability.)
      var vid = getVaultId();
      var es = new EventSource(getServerUrl() + "/events" + (vid ? "?vault=" + encodeURIComponent(vid) : ""));
      events = es;
      es.onopen = function () {
        sseRetryMs = 5000;
      };
      es.addEventListener("changed", function () {
        syncSoon();
      });
      es.onerror = function () {
        // Dropped connections auto-reconnect, but a non-200 response (the
        // server's 503 at its SSE connection cap) fatally CLOSEs the
        // EventSource per spec — the browser never retries it. Rebuild it
        // ourselves with backoff so one transient cap hit doesn't kill change
        // notifications for the whole session.
        if (events === es && es.readyState === EventSource.CLOSED) {
          unsubscribe();
          sseRetryTimer = setTimeout(subscribe, sseRetryMs);
          sseRetryMs = Math.min(sseRetryMs * 2, 60000);
        }
      };
    } catch (e) {
      /* ignore */
    }
  }

  function unsubscribe() {
    clearTimeout(sseRetryTimer);
    if (events) {
      try {
        events.close();
      } catch (e) {
        /* ignore */
      }
      events = null;
    }
  }

  // Called after unlock. By now a local vault exists, so guarantee it has a
  // namespace (covers vaults created before namespacing, and offline-first
  // vaults whose first sync is only being enabled now).
  function start() {
    if (!isEnabled()) return;
    ensureVaultId();
    subscribe();
    syncNow();
  }

  function stop() {
    unsubscribe();
  }

  return {
    isEnabled: isEnabled,
    setEnabled: setEnabled,
    getToken: getToken,
    setToken: setToken,
    getServerUrl: getServerUrl,
    setServerUrl: setServerUrl,
    getVaultId: getVaultId,
    setVaultId: setVaultId,
    newVaultId: newVaultId,
    ensureVaultId: ensureVaultId,
    onStatus: onStatus,
    getStatus: getStatus,
    syncNow: syncNow,
    syncSoon: syncSoon,
    bootstrap: bootstrap,
    checkAuth: checkAuth,
    makeSetupCode: makeSetupCode,
    parseSetupCode: parseSetupCode,
    fetchSetupQR: fetchSetupQR,
    start: start,
    stop: stop
  };
})();
