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
 *   syncToken (bearer token for public servers),
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

  var TOKEN_KEY = "syncToken";
  var SERVER_KEY = "serverUrl";
  var REG_KEY = "vaults"; // JSON array of known vault ids, in display order
  var CURRENT_KEY = "currentVault"; // last-used id; read only at page load
  var DEBOUNCE_MS = 600;

  var listeners = [];
  var lastStatus = { state: "idle", ok: true, message: "", conflicts: 0 };
  var syncing = false;
  var queued = false;
  var events = null;
  var debounceTimer = null;

  /* ---------- config (all per-vault) ---------- */

  // Every config value is stored under "<base>:<vaultId>" for the ACTIVE
  // vault (vault.js owns the active id; there is no unsuffixed fallback).
  // With no vault selected the getters read a nonexistent key and return ""
  // — the gate flows always select a vault before storing anything.
  function cfgKey(base) {
    return base + ":" + (window.Vault ? Vault.getActiveId() : "");
  }

  function getToken() {
    try {
      return localStorage.getItem(cfgKey(TOKEN_KEY)) || "";
    } catch (e) {
      return "";
    }
  }

  function setToken(t) {
    try {
      localStorage.setItem(cfgKey(TOKEN_KEY), t || "");
    } catch (e) {
      /* ignore */
    }
  }

  function getServerUrl() {
    try {
      // Normalized without a trailing slash so paths concatenate cleanly.
      return (localStorage.getItem(cfgKey(SERVER_KEY)) || "").replace(/\/+$/, "");
    } catch (e) {
      return "";
    }
  }

  function setServerUrl(u) {
    try {
      localStorage.setItem(cfgKey(SERVER_KEY), (u || "").trim().replace(/\/+$/, ""));
    } catch (e) {
      /* ignore */
    }
  }

  // The active id IS the vault identity — no separate stored copy to drift.
  function getVaultId() {
    return window.Vault ? Vault.getActiveId() : "";
  }

  // Register + select. Kept under this name because it is the shape every
  // caller wants (connect, restore, the extension's ov:connect): "this id is
  // now a vault on this device, and it is the one I mean".
  function setVaultId(id) {
    if (!id) return;
    addVault(id);
    selectVault(id);
  }

  /* ---------- vault registry ---------- */

  function listVaults() {
    try {
      var ids = JSON.parse(localStorage.getItem(REG_KEY) || "[]");
      return Array.isArray(ids) ? ids : [];
    } catch (e) {
      return [];
    }
  }

  function saveVaults(ids) {
    try {
      localStorage.setItem(REG_KEY, JSON.stringify(ids));
    } catch (e) {
      /* ignore */
    }
  }

  function addVault(id) {
    var ids = listVaults();
    if (ids.indexOf(id) < 0) {
      ids.push(id);
      saveVaults(ids);
    }
  }

  // Forget one vault's registration and config. Names keys owned elsewhere
  // (syncCursor: vault.js, vaultName: app.js) on purpose: one removal site
  // beats three cross-module one-call methods. The vault's DATABASE is
  // deleted separately (Vault.wipeLocal) — the caller sequences both.
  function removeVault(id) {
    saveVaults(
      listVaults().filter(function (v) {
        return v !== id;
      })
    );
    try {
      localStorage.removeItem(TOKEN_KEY + ":" + id);
      localStorage.removeItem(SERVER_KEY + ":" + id);
      localStorage.removeItem("syncCursor:" + id);
      localStorage.removeItem("vaultName:" + id);
      if (localStorage.getItem(CURRENT_KEY) === id) {
        localStorage.removeItem(CURRENT_KEY);
      }
    } catch (e) {
      /* ignore */
    }
  }

  // Make a vault the active one for this tab and remember it as the last
  // used. Locks via Vault.use, and resets the status line so a stale sync
  // state or conflict count never leaks across vaults. Does NOT register the
  // id — a probe of an unknown vault must not leave a ghost registration.
  function selectVault(id) {
    if (window.Vault) Vault.use(id);
    demoExpires = 0; // belongs to the vault being left, not the one arriving
    try {
      localStorage.setItem(CURRENT_KEY, id);
    } catch (e) {
      /* ignore */
    }
    emit({ state: "idle", ok: true, message: "", conflicts: 0 });
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

  // Guarantee this tab has an active vault (used the moment a local vault
  // exists so sync has a namespace to push into). Never overrides one.
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

  // Unix seconds at which a demo server deletes the active vault; 0 when the
  // server is not a demo, or has not been reached yet this session.
  var demoExpires = 0;

  function getDemoExpires() {
    return demoExpires;
  }

  /* ---------- HTTP ---------- */

  function headers(extra) {
    var h = extra || {};
    // A caller-set token wins (same rule as X-Vault-Write below): checkAuth
    // probes the typed token before any vault id exists to store it under.
    // Presence check, not truthiness: an explicitly EMPTY override must
    // suppress the stored token too, or the probe would vouch for another
    // vault's token while "" is what actually gets stored.
    var t = getToken();
    if (t && !("X-Vault-Token" in h)) h["X-Vault-Token"] = t;
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

  // 507 means the server has room for the vault but not for this write — a
  // demo server's per-vault cap. The body is the reason, written for a person,
  // so carry it through to the sync status instead of a bare status code.
  function limitError(res) {
    return res.text().then(function (t) {
      throw { limit: true, message: (t || "").trim() };
    });
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
            // Only a demo server sends this: the unix time at which it
            // deletes this vault. Absent everywhere else, which is what
            // keeps the demo notice off a real vault.
            demoExpires = data.demoExpires || 0;
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
            if (res.status === 507) return limitError(res);
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
            if (res.status === 507) return limitError(res);
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
        } else if (err && err.limit) {
          emit({
            state: "error",
            ok: false,
            message: err.message || "This vault is full",
            conflicts: lastStatus.conflicts
          });
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

  // The setup code wrapped as a link: scanned by a bare camera app it opens
  // the app with the code in the fragment (never sent to the server), instead
  // of being handed to a search engine as opaque text. The in-app scanner and
  // the connect field unwrap it via parseSetupCode.
  function makeSetupLink() {
    var origin =
      getServerUrl() || (window.location && window.location.origin) || "";
    return origin + "/#" + makeSetupCode();
  }

  // {vaultId, token, url}, or null when str isn't a setup code (callers fall
  // back to treating it as a bare Vault ID). Accepts the bare code or the
  // makeSetupLink URL form (pasted or scanned).
  function parseSetupCode(str) {
    str = (str || "").trim();
    if (/^https?:\/\//i.test(str)) {
      var h = str.indexOf("#");
      if (h < 0) return null;
      str = str.slice(h + 1);
    }
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
      body: JSON.stringify({ text: makeSetupLink() })
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
  function checkAuth(tokenOverride) {
    // A string argument (even "") probes exactly that token — the one the
    // caller is about to store — never the active vault's stored token.
    var opts;
    if (typeof tokenOverride === "string") {
      opts = { headers: { "X-Vault-Token": tokenOverride } };
    }
    return api("/api/state", opts).then(
      function (res) {
        return { needsAuth: res.status === 401, offline: false };
      },
      function () {
        return { needsAuth: false, offline: true };
      }
    );
  }

  function syncSoon() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(syncNow, DEBOUNCE_MS);
  }

  /* ---------- SSE: react to other devices ---------- */

  var sseRetryTimer = null;
  var sseRetryMs = 5000;

  function subscribe() {
    if (events) return;
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
  // namespace (covers vaults created before namespacing).
  function start() {
    ensureVaultId();
    subscribe();
    syncNow();
  }

  function stop() {
    unsubscribe();
  }

  // Point this tab at the last-used vault (or the first known one if that
  // record is stale). Read-only: currentVault is only WRITTEN by an explicit
  // selection, so a mere page load never steals "last used" from another
  // tab. app.js may override this from an installed icon's ?vault= parameter
  // before anything opens a database. This same block is what reopens the
  // extension's single vault after a browser restart.
  (function () {
    var ids = listVaults();
    if (!ids.length) return;
    var cur = "";
    try {
      cur = localStorage.getItem(CURRENT_KEY) || "";
    } catch (e) {
      /* ignore */
    }
    if (ids.indexOf(cur) < 0) cur = ids[0];
    if (window.Vault) Vault.use(cur);
  })();

  return {
    getToken: getToken,
    setToken: setToken,
    getServerUrl: getServerUrl,
    setServerUrl: setServerUrl,
    getVaultId: getVaultId,
    setVaultId: setVaultId,
    newVaultId: newVaultId,
    ensureVaultId: ensureVaultId,
    listVaults: listVaults,
    addVault: addVault,
    removeVault: removeVault,
    selectVault: selectVault,
    onStatus: onStatus,
    getStatus: getStatus,
    getDemoExpires: getDemoExpires,
    syncNow: syncNow,
    syncSoon: syncSoon,
    bootstrap: bootstrap,
    checkAuth: checkAuth,
    makeSetupCode: makeSetupCode,
    makeSetupLink: makeSetupLink,
    parseSetupCode: parseSetupCode,
    fetchSetupQR: fetchSetupQR,
    start: start,
    stop: stop
  };
})();
