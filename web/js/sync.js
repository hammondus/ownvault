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
 *   syncEnabled ("0" disables), syncToken (bearer token for public servers).
 */
window.Sync = (function () {
  "use strict";

  var ENABLED_KEY = "syncEnabled";
  var TOKEN_KEY = "syncToken";
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
        var metaP = data.meta
          ? Vault.applyMeta(data.meta.doc, data.meta.rev)
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
      .then(function (items) {
        if (!items.length) return;
        return api("/api/push", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ entries: items })
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
  }

  // Full sync cycle. Never rejects: offline is a normal state, surfaced via
  // status rather than an error.
  function syncNow() {
    if (!isEnabled()) return Promise.resolve();
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
  // whether a vault now exists locally.
  function bootstrap() {
    if (!isEnabled()) return Vault.isInitialized();
    return pull().then(
      function () {
        return Vault.isInitialized();
      },
      function () {
        return Vault.isInitialized();
      }
    );
  }

  function syncSoon() {
    if (!isEnabled()) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(syncNow, DEBOUNCE_MS);
  }

  /* ---------- SSE: react to other devices ---------- */

  function subscribe() {
    if (events || !isEnabled()) return;
    try {
      events = new EventSource("/events");
      events.addEventListener("changed", function () {
        syncSoon();
      });
      events.onerror = function () {
        /* EventSource auto-reconnects */
      };
    } catch (e) {
      /* ignore */
    }
  }

  function unsubscribe() {
    if (events) {
      try {
        events.close();
      } catch (e) {
        /* ignore */
      }
      events = null;
    }
  }

  // Called after unlock.
  function start() {
    if (!isEnabled()) return;
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
    onStatus: onStatus,
    getStatus: getStatus,
    syncNow: syncNow,
    syncSoon: syncSoon,
    bootstrap: bootstrap,
    start: start,
    stop: stop
  };
})();
