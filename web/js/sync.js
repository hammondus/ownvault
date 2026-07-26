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
 *   vaultId (which namespace on the server this device's vault lives in).
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
    return h;
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = headers(opts.headers);
    return fetch(path, opts);
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
    return Vault.pendingMeta()
      .then(function (metaDoc) {
        if (!metaDoc) return;
        return api("/api/meta", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ doc: metaDoc })
        })
          .then(function (res) {
            if (res.status === 401) throw { auth: true };
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
      var es = new EventSource("/events" + (vid ? "?vault=" + encodeURIComponent(vid) : ""));
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
    getVaultId: getVaultId,
    setVaultId: setVaultId,
    newVaultId: newVaultId,
    ensureVaultId: ensureVaultId,
    onStatus: onStatus,
    getStatus: getStatus,
    syncNow: syncNow,
    syncSoon: syncSoon,
    bootstrap: bootstrap,
    start: start,
    stop: stop
  };
})();
