/*
 * Own Vault — encrypted vault core.
 *
 * Deliberately DOM-free and self-contained: crypto, storage, and the entry
 * CRUD/export/import live here so the same module can later back a browser
 * extension as well as this PWA. UI glue lives in vaultui.js.
 *
 * Crypto model (see CLAUDE.md):
 *   - A random AES-GCM "vault key" encrypts every entry individually.
 *   - master password -> PBKDF2 -> "wrapping key", which encrypts only the
 *     vault key. The wrapped-key record (wrapped vault key + salt + iters) is
 *     the single unlock artifact; a wrong password is an AES-GCM auth failure
 *     unwrapping it, so no password hash is stored.
 *   - Changing the master password re-wraps the vault key (one small write),
 *     never re-encrypts entries.
 *
 * Storage (IndexedDB):
 *   - meta store: the wrapped-key record under key "vault".
 *   - entries store: envelopes {id, iv, ciphertext, updatedAt, deleted}.
 *     ciphertext decrypts to the payload {title, username, password, url,
 *     notes, created, modified}. Deletes are tombstones (deleted=true, payload
 *     dropped) so they can sync later.
 */
window.Vault = (function () {
  "use strict";

  var DB_NAME = "ownvault";
  var DB_VERSION = 1;
  var STORE_META = "meta";
  var STORE_ENTRIES = "entries";
  var META_KEY = "vault";

  // A reserved entry holding vault-level settings (currently just the vault
  // name) as an encrypted, synced payload — so the name follows the vault to
  // new devices without the server ever seeing it. It rides the normal per-entry
  // sync (proper per-entry concurrency + tombstones), deliberately NOT the
  // wrapped-key meta doc (whose server write is last-writer-wins, so bundling a
  // user-editable name there could clobber a password change). It's hidden from
  // the passwords list/search/count and never raises a user conflict.
  var SETTINGS_ID = "__vault__";

  // PBKDF2-SHA256 work factor. High by design: the wrapped key is the only
  // thing standing between an attacker with the ciphertext and the vault.
  var PBKDF2_ITERATIONS = 600000;
  // Bounds on the iteration count accepted from synced meta docs and backup
  // files. Tampering can't reveal anything (the unwrap just fails), but an
  // absurd count from a hostile server would hang the device deriving the
  // key, and the floor keeps any future path from quietly downgrading the KDF.
  var MIN_ITERATIONS = 100000;
  var MAX_ITERATIONS = 10000000;
  var EXPORT_MAGIC = "ownvault.backup";
  // v2 adds the (non-secret) vaultId so a restore can reattach to the same
  // server namespace. v1 files (no vaultId) still import — they just merge into
  // whatever vault the restoring device is already on.
  var EXPORT_VERSION = 2;

  var subtle = window.crypto.subtle;

  var db = null; // IDBDatabase, opened lazily
  var vaultKey = null; // CryptoKey when unlocked, else null
  var changeCb = null; // notified after any entry mutation

  /* ==================== small helpers ==================== */

  function randomBytes(n) {
    return window.crypto.getRandomValues(new Uint8Array(n));
  }

  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  function utf8Decode(buf) {
    return new TextDecoder().decode(buf);
  }

  function toU8(buf) {
    return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  }

  // base64 only for the export file (JSON can't carry binary); IndexedDB
  // stores the Uint8Arrays directly via structured clone.
  function b64encode(bytes) {
    var u8 = toU8(bytes);
    var s = "";
    for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return window.btoa(s);
  }

  function b64decode(str) {
    var s = window.atob(str);
    var u8 = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }

  /* ==================== IndexedDB ==================== */

  function openDB() {
    if (db) return Promise.resolve(db);
    return new Promise(function (resolve, reject) {
      var req = window.indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function () {
        var d = req.result;
        if (!d.objectStoreNames.contains(STORE_META)) {
          d.createObjectStore(STORE_META);
        }
        if (!d.objectStoreNames.contains(STORE_ENTRIES)) {
          d.createObjectStore(STORE_ENTRIES, { keyPath: "id" });
        }
      };
      req.onsuccess = function () {
        db = req.result;
        resolve(db);
      };
      req.onerror = function () {
        reject(req.error);
      };
    });
  }

  function tx(store, mode, fn) {
    return openDB().then(function (d) {
      return new Promise(function (resolve, reject) {
        var t = d.transaction(store, mode);
        var request = fn(t.objectStore(store));
        t.oncomplete = function () {
          resolve(request ? request.result : undefined);
        };
        t.onerror = function () {
          reject(t.error);
        };
        t.onabort = function () {
          reject(t.error);
        };
      });
    });
  }

  function metaGet() {
    return tx(STORE_META, "readonly", function (s) {
      return s.get(META_KEY);
    });
  }

  function metaPut(record) {
    return tx(STORE_META, "readwrite", function (s) {
      s.put(record, META_KEY);
    });
  }

  function entriesGetAll() {
    return tx(STORE_ENTRIES, "readonly", function (s) {
      return s.getAll();
    });
  }

  function entryGetRaw(id) {
    return tx(STORE_ENTRIES, "readonly", function (s) {
      return s.get(id);
    });
  }

  function entryPutRaw(envelope) {
    return tx(STORE_ENTRIES, "readwrite", function (s) {
      s.put(envelope);
    });
  }

  /* ==================== crypto ==================== */

  function validIterations(n) {
    return (
      typeof n === "number" &&
      isFinite(n) &&
      n >= MIN_ITERATIONS &&
      n <= MAX_ITERATIONS
    );
  }

  function deriveWrappingKey(password, salt, iterations) {
    if (!validIterations(iterations)) {
      return Promise.reject(new Error("implausible KDF iteration count"));
    }
    return subtle
      .importKey("raw", utf8Encode(password), "PBKDF2", false, ["deriveKey"])
      .then(function (baseKey) {
        return subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: toU8(salt),
            iterations: iterations,
            hash: "SHA-256"
          },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
      });
  }

  function aesEncrypt(key, plaintextBytes) {
    var iv = randomBytes(12);
    return subtle
      .encrypt({ name: "AES-GCM", iv: iv }, key, plaintextBytes)
      .then(function (ct) {
        return { iv: iv, ciphertext: new Uint8Array(ct) };
      });
  }

  function aesDecrypt(key, iv, ciphertext) {
    return subtle
      .decrypt({ name: "AES-GCM", iv: toU8(iv) }, key, toU8(ciphertext))
      .then(function (pt) {
        return new Uint8Array(pt);
      });
  }

  // Build a fresh wrapped-key record around an (already imported) vault key,
  // using the given password. Returns the meta record to store.
  function wrapVaultKey(rawVaultKey, password) {
    var salt = randomBytes(16);
    return deriveWrappingKey(password, salt, PBKDF2_ITERATIONS).then(function (
      wrappingKey
    ) {
      return aesEncrypt(wrappingKey, rawVaultKey).then(function (out) {
        return {
          v: 1,
          salt: salt,
          iterations: PBKDF2_ITERATIONS,
          wrapIv: out.iv,
          wrapped: out.ciphertext
        };
      });
    });
  }

  // Returns the raw vault-key bytes on success; rejects on wrong password
  // (AES-GCM auth failure) or a malformed record.
  function unwrapVaultKey(record, password) {
    return deriveWrappingKey(password, record.salt, record.iterations).then(
      function (wrappingKey) {
        return aesDecrypt(wrappingKey, record.wrapIv, record.wrapped);
      }
    );
  }

  function importVaultKey(rawBytes) {
    // extractable: false — nothing ever exports the live key (change-password
    // and backup both work from the wrapped record, not the CryptoKey), so
    // script running in the page (XSS, a hostile extension) can *use* the key
    // while unlocked but can never read the key material itself.
    return subtle.importKey("raw", toU8(rawBytes), { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt"
    ]);
  }

  /* ==================== entry payload <-> envelope ==================== */

  // v2 entry-ciphertext format: a 4-byte magic prefix ("OV2\0") followed by
  // AES-GCM output produced with the entry id as additionalData. Binding the
  // id into the GCM tag stops a malicious server swapping ciphertexts between
  // entries — every entry shares the vault key, so an *unbound* blob would
  // decrypt fine under any id. Legacy (unprefixed) ciphertexts still decrypt
  // without AAD and are rebound the next time the entry is written; the magic
  // is what lets us refuse the unbound fallback for entries known to be bound.
  var CT_MAGIC = new Uint8Array([0x4f, 0x56, 0x32, 0x00]); // "OV2\0"

  function hasCtMagic(u8) {
    return (
      u8.length > CT_MAGIC.length &&
      u8[0] === CT_MAGIC[0] &&
      u8[1] === CT_MAGIC[1] &&
      u8[2] === CT_MAGIC[2] &&
      u8[3] === CT_MAGIC[3]
    );
  }

  function encryptForEntry(id, plaintextBytes) {
    var iv = randomBytes(12);
    return subtle
      .encrypt(
        { name: "AES-GCM", iv: iv, additionalData: utf8Encode(id) },
        vaultKey,
        plaintextBytes
      )
      .then(function (ct) {
        var body = toU8(ct);
        var out = new Uint8Array(CT_MAGIC.length + body.length);
        out.set(CT_MAGIC, 0);
        out.set(body, CT_MAGIC.length);
        return { iv: iv, ciphertext: out };
      });
  }

  // Decrypt an entry ciphertext: id-bound (v2) when the magic prefix is
  // present, legacy (no AAD) otherwise. The one-in-2^32 legacy blob that
  // happens to start with the magic bytes fails the bound attempt and falls
  // back to a legacy decrypt of the whole blob.
  function decryptForEntry(id, iv, ciphertext) {
    var ct = toU8(ciphertext);
    if (hasCtMagic(ct)) {
      return subtle
        .decrypt(
          { name: "AES-GCM", iv: toU8(iv), additionalData: utf8Encode(id) },
          vaultKey,
          ct.subarray(CT_MAGIC.length)
        )
        .then(
          function (pt) {
            return new Uint8Array(pt);
          },
          function () {
            return aesDecrypt(vaultKey, iv, ct);
          }
        );
    }
    return aesDecrypt(vaultKey, iv, ct);
  }

  function encryptPayload(id, payload) {
    var bytes = utf8Encode(JSON.stringify(payload));
    return encryptForEntry(id, bytes);
  }

  function decryptEnvelope(env) {
    return decryptForEntry(env.id, env.iv, env.ciphertext).then(function (bytes) {
      var payload = JSON.parse(utf8Decode(bytes));
      payload.id = env.id;
      payload.updatedAt = env.updatedAt;
      payload.conflict = !!env.conflict;
      return payload;
    });
  }

  // local=true marks a genuine local edit (add/edit/delete/import) that needs
  // pushing. Sync-applied changes (applyPulled/confirmPushed/resolveConflict)
  // call this with no arg so the listener refreshes the UI but does NOT schedule
  // another sync — otherwise every sync's own refresh would re-trigger a sync,
  // polling forever. Note the `=== true` guard: several callers use
  // `.then(notifyChanged)`, which would otherwise pass the promise's resolved
  // value in as `local`.
  function notifyChanged(local) {
    if (typeof changeCb === "function") changeCb(local === true);
  }

  function requireUnlocked() {
    if (!vaultKey) throw new Error("vault is locked");
  }

  /* ==================== public API ==================== */

  // Ask the browser to keep our storage from being evicted under pressure.
  // Best-effort: a denied request just leaves the default (evictable) policy.
  function requestPersistence() {
    if (navigator.storage && navigator.storage.persist) {
      try {
        return navigator.storage.persist();
      } catch (e) {
        /* ignore */
      }
    }
    return Promise.resolve(false);
  }

  function isInitialized() {
    return metaGet().then(function (r) {
      return !!r;
    });
  }

  function isUnlocked() {
    return !!vaultKey;
  }

  // First run: generate a vault key, wrap it under the chosen password, and
  // leave the vault unlocked.
  function create(password) {
    return isInitialized().then(function (exists) {
      if (exists) throw new Error("vault already initialized");
      var rawVaultKey = randomBytes(32);
      return wrapVaultKey(rawVaultKey, password)
        .then(function (record) {
          record.rev = 0;
          record.dirty = true; // needs pushing to the server on first sync
          return metaPut(record);
        })
        .then(function () {
          return importVaultKey(rawVaultKey);
        })
        .then(function (key) {
          vaultKey = key;
          requestPersistence();
        });
    });
  }

  // Returns true on success, false on a wrong password. Other failures (no
  // vault, corrupt record) reject.
  function unlock(password) {
    return metaGet().then(function (record) {
      if (!record) throw new Error("vault not initialized");
      return unwrapVaultKey(record, password)
        .then(function (rawVaultKey) {
          return importVaultKey(rawVaultKey);
        })
        .then(function (key) {
          vaultKey = key;
          requestPersistence();
          return true;
        })
        .catch(function () {
          // AES-GCM auth failure === wrong password.
          return false;
        });
    });
  }

  function lock() {
    vaultKey = null;
  }

  // Re-wrap the same vault key under a new password. Verifies the old
  // password first. One small atomic write — entries are untouched.
  function changePassword(oldPassword, newPassword) {
    return metaGet().then(function (record) {
      if (!record) throw new Error("vault not initialized");
      return unwrapVaultKey(record, oldPassword).then(
        function (rawVaultKey) {
          return wrapVaultKey(rawVaultKey, newPassword)
            .then(function (newRecord) {
              newRecord.rev = record.rev || 0;
              newRecord.dirty = true; // re-wrapped record must sync out
              return metaPut(newRecord);
            })
            .then(function () {
              return true;
            });
        },
        function () {
          return false; // old password wrong
        }
      );
    });
  }

  // Decrypted, non-deleted entries. Callers search/sort in memory.
  function list() {
    requireUnlocked();
    return entriesGetAll().then(function (envs) {
      var live = envs.filter(function (e) {
        return !e.deleted && e.id !== SETTINGS_ID; // hide the reserved settings record
      });
      // Skip anything that won't decrypt (e.g. foreign data pulled from a
      // shared server) rather than failing the whole list.
      return Promise.all(
        live.map(function (e) {
          return decryptEnvelope(e).catch(function () {
            return null;
          });
        })
      ).then(function (rows) {
        return rows.filter(Boolean);
      });
    });
  }

  function get(id) {
    requireUnlocked();
    return entryGetRaw(id).then(function (env) {
      if (!env || env.deleted) return null;
      return decryptEnvelope(env);
    });
  }

  function newId() {
    return window.crypto.randomUUID
      ? window.crypto.randomUUID()
      : b64encode(randomBytes(16));
  }

  // Create (no id) or update (id present). Stamps created/modified inside the
  // encrypted payload and updatedAt on the envelope (server-visible for sync).
  // Marks the entry dirty and keeps its existing rev as the sync base.
  function put(fields) {
    requireUnlocked();
    var now = Date.now();
    var isNew = !fields.id;
    var id = fields.id || newId();
    var payload = {
      title: fields.title || "",
      username: fields.username || "",
      password: fields.password || "",
      url: fields.url || "",
      notes: fields.notes || "",
      // "critical" marks an entry for the printed emergency recovery sheet
      // (crypto seeds, master passwords, 2FA backup codes). Just another
      // encrypted payload field — never server-visible.
      critical: !!fields.critical,
      created: fields.created || now,
      modified: now
    };
    var priorP = isNew ? Promise.resolve(null) : entryGetRaw(id);
    return priorP.then(function (prior) {
      return encryptPayload(id, payload).then(function (enc) {
        var env = {
          id: id,
          iv: enc.iv,
          ciphertext: enc.ciphertext,
          updatedAt: now,
          deleted: false,
          rev: prior ? prior.rev || 0 : 0,
          dirty: true,
          conflict: false,
          remote: null
        };
        return entryPutRaw(env).then(function () {
          notifyChanged(true);
          payload.id = id;
          payload.updatedAt = now;
          return payload;
        });
      });
    });
  }

  // Tombstone: keep id + updatedAt + deleted so the delete can sync; drop the
  // ciphertext so no plaintext lingers. Preserves rev as the sync base.
  function remove(id) {
    requireUnlocked();
    return entryGetRaw(id).then(function (prior) {
      return entryPutRaw({
        id: id,
        iv: null,
        ciphertext: null,
        updatedAt: Date.now(),
        deleted: true,
        rev: prior ? prior.rev || 0 : 0,
        dirty: true,
        conflict: false,
        remote: null
      }).then(function () {
        notifyChanged(true);
      });
    });
  }

  /* ==================== CSV import ==================== */
  // Import from another password manager's CSV export. Parsing and mapping
  // live here (DOM-free, reusable by a future extension); the UI reads the
  // file, shows the parsed count for confirmation, then calls putMany.

  // Minimal RFC 4180 parser: quoted fields may hold the delimiter, doubled
  // quotes, and newlines. Accepts \n or \r\n row ends and a UTF-8 BOM.
  function parseCSVRows(text, delim) {
    var rows = [];
    var row = [];
    var field = "";
    var inQ = false;
    var i = 0;
    var c;
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    while (i < text.length) {
      c = text[i];
      if (inQ) {
        if (c === '"') {
          if (text[i + 1] === '"') {
            field += '"';
            i += 2;
            continue;
          }
          inQ = false;
          i++;
          continue;
        }
        field += c;
        i++;
        continue;
      }
      if (c === '"' && field === "") {
        inQ = true;
        i++;
        continue;
      }
      if (c === delim) {
        row.push(field);
        field = "";
        i++;
        continue;
      }
      if (c === "\n" || c === "\r") {
        if (c === "\r" && text[i + 1] === "\n") i++;
        row.push(field);
        field = "";
        rows.push(row);
        row = [];
        i++;
        continue;
      }
      field += c;
      i++;
    }
    if (field !== "" || row.length) {
      row.push(field);
      rows.push(row);
    }
    return rows.filter(function (r) {
      return r.some(function (f) {
        return f !== "";
      });
    });
  }

  // Header names seen in the wild, matched after normalising (lowercase,
  // alphanumerics only — so "Login Name", "login_name" and "loginName" all
  // read as "loginname"). First candidate present wins. Covers Chrome/Edge
  // (name,url,username,password,note), Firefox (url,username,password — no
  // title, derived from the url), Safari/Apple Passwords (Title,URL,Username,
  // Password,Notes,OTPAuth), Bitwarden (name,notes,login_uri,login_username,
  // login_password,login_totp), LastPass (url,username,password,extra,name),
  // 1Password (Title,Url,Username,Password,Notes) and KeePass/KeePassXC
  // (Account/Title, Login Name/Username, Password, Web Site/URL, Comments).
  var CSV_HEADERS = {
    title: ["title", "name", "account"],
    username: ["username", "loginname", "loginusername", "user"],
    password: ["password", "loginpassword"],
    url: ["url", "loginuri", "website", "site", "webaddress"],
    notes: ["notes", "note", "extra", "comments", "comment"],
    totp: ["totp", "logintotp", "otpauth", "otp"]
  };

  function normHeader(h) {
    return String(h || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function hostFromUrl(u) {
    var m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^\/:?#]+)/i.exec(u || "");
    return m ? m[1] : "";
  }

  // Parse a CSV export into entry field objects WITHOUT writing anything, so
  // the UI can show the count before the user commits. Throws on anything
  // that doesn't look like a password export. Returns {entries, skipped}.
  function parseCSV(text) {
    // Some exports (older KeePass, spreadsheet re-saves in EU locales) are
    // semicolon-separated; decide from the header line.
    var nl = text.indexOf("\n");
    var head = nl === -1 ? text : text.slice(0, nl);
    var delim = head.indexOf(",") === -1 && head.indexOf(";") !== -1 ? ";" : ",";
    var rows = parseCSVRows(text, delim);
    if (rows.length < 2) {
      throw new Error("No entries found — the file has a header row but no data.");
    }
    var header = rows[0].map(normHeader);
    var col = {};
    Object.keys(CSV_HEADERS).forEach(function (target) {
      var cands = CSV_HEADERS[target];
      for (var i = 0; i < cands.length; i++) {
        var at = header.indexOf(cands[i]);
        if (at !== -1) {
          col[target] = at;
          return;
        }
      }
    });
    // Every real password export has a password column; without one this is
    // some other CSV and silently importing it would only make a mess.
    if (col.password === undefined) {
      throw new Error(
        "Couldn't recognise this as a password export — no password column in the header."
      );
    }
    var entries = [];
    var skipped = 0;
    rows.slice(1).forEach(function (r) {
      function v(k) {
        return col[k] === undefined ? "" : String(r[col[k]] || "").trim();
      }
      var notes = v("notes");
      var totp = v("totp");
      // No TOTP field in the payload (yet) — keep the secret in notes rather
      // than silently dropping it.
      if (totp) notes = (notes ? notes + "\n" : "") + "TOTP: " + totp;
      var e = {
        title: v("title"),
        username: v("username"),
        password: v("password"),
        url: v("url"),
        notes: notes
      };
      if (!e.title && !e.username && !e.password && !e.notes) {
        skipped++;
        return;
      }
      if (!e.title) e.title = hostFromUrl(e.url) || e.username || "(imported)";
      entries.push(e);
    });
    if (!entries.length) {
      throw new Error("No entries found in that file.");
    }
    return { entries: entries, skipped: skipped };
  }

  // Bulk add: encrypt every entry first, then write them in ONE IndexedDB
  // transaction with a single change notification — importing a few hundred
  // rows must not fire a few hundred list refreshes and sync schedules.
  // Always creates new entries (fresh ids); nothing is overwritten.
  function putMany(list) {
    requireUnlocked();
    var now = Date.now();
    return Promise.all(
      (list || []).map(function (fields) {
        var id = newId();
        var payload = {
          title: fields.title || "",
          username: fields.username || "",
          password: fields.password || "",
          url: fields.url || "",
          notes: fields.notes || "",
          critical: !!fields.critical,
          created: now,
          modified: now
        };
        return encryptPayload(id, payload).then(function (enc) {
          return {
            id: id,
            iv: enc.iv,
            ciphertext: enc.ciphertext,
            updatedAt: now,
            deleted: false,
            rev: 0,
            dirty: true,
            conflict: false,
            remote: null
          };
        });
      })
    ).then(function (envs) {
      return openDB().then(function (d) {
        return new Promise(function (resolve, reject) {
          var t = d.transaction(STORE_ENTRIES, "readwrite");
          var s = t.objectStore(STORE_ENTRIES);
          envs.forEach(function (env) {
            s.put(env);
          });
          t.oncomplete = function () {
            notifyChanged(true);
            resolve(envs.length);
          };
          t.onerror = function () {
            reject(t.error);
          };
          t.onabort = function () {
            reject(t.error);
          };
        });
      });
    });
  }

  /* ==================== vault settings (name) ==================== */

  // Decrypt the reserved settings record into an object ({name, ...}), or {} if
  // absent / undecryptable. Requires an unlocked vault (uses the vault key).
  function settingsGet() {
    requireUnlocked();
    return entryGetRaw(SETTINGS_ID).then(function (env) {
      if (!env || env.deleted || !env.ciphertext) return {};
      return decryptForEntry(SETTINGS_ID, env.iv, env.ciphertext)
        .then(function (bytes) {
          try {
            return JSON.parse(utf8Decode(bytes)) || {};
          } catch (e) {
            return {};
          }
        })
        .catch(function () {
          return {};
        });
    });
  }

  // The vault's synced display name ("" if never set).
  function getName() {
    return settingsGet().then(function (s) {
      return s.name || "";
    });
  }

  // Set the vault name: merge into the settings payload, encrypt, and store as a
  // dirty entry so it syncs to other devices like any edit (rev-based OCC).
  function setName(name) {
    requireUnlocked();
    return entryGetRaw(SETTINGS_ID).then(function (prior) {
      return settingsGet().then(function (cur) {
        cur.name = name || "";
        var now = Date.now();
        return encryptForEntry(SETTINGS_ID, utf8Encode(JSON.stringify(cur))).then(
          function (enc) {
            return entryPutRaw({
              id: SETTINGS_ID,
              iv: enc.iv,
              ciphertext: enc.ciphertext,
              updatedAt: now,
              deleted: false,
              rev: prior ? prior.rev || 0 : 0,
              dirty: true,
              conflict: false,
              remote: null
            }).then(function () {
              notifyChanged(true);
            });
          }
        );
      });
    });
  }

  // Full encrypted snapshot: the wrapped-key record plus every envelope, all
  // still ciphertext. The file is only openable with the master password that
  // made it. Works offline; the vault need not even be unlocked to export.
  //
  // vaultId (optional, passed in by the caller since it's a sync-layer concern,
  // not crypto) is recorded so a restore can rejoin the same server namespace.
  // It's an unguessable id, not a secret, and the payload is encrypted anyway.
  function exportVault(vaultId) {
    return Promise.all([metaGet(), entriesGetAll()]).then(function (res) {
      var record = res[0];
      var envs = res[1] || [];
      if (!record) throw new Error("nothing to export");
      var doc = {
        magic: EXPORT_MAGIC,
        version: EXPORT_VERSION,
        exportedAt: Date.now(),
        vaultId: vaultId || "",
        meta: {
          v: record.v,
          salt: b64encode(record.salt),
          iterations: record.iterations,
          wrapIv: b64encode(record.wrapIv),
          wrapped: b64encode(record.wrapped)
        },
        entries: envs.map(function (e) {
          return {
            id: e.id,
            iv: e.iv ? b64encode(e.iv) : null,
            ciphertext: e.ciphertext ? b64encode(e.ciphertext) : null,
            updatedAt: e.updatedAt,
            deleted: !!e.deleted
          };
        })
      };
      return new Blob([JSON.stringify(doc)], { type: "application/json" });
    });
  }

  // Restore a backup: replaces the whole local vault (meta + entries) with the
  // file's contents. After import, unlock with the password that made the
  // export. Locks the current session so stale keys aren't reused.
  //
  // Sync interaction (merge, backup wins): imported entries are marked
  // `restored` + `dirty` and the cursor is reset to 0, so the next sync pulls
  // the server's current state, rebases each restored entry onto the server's
  // rev (see applyPulled) and pushes it — the backup overwrites matching
  // server entries and revives ones it had deleted, while entries that exist
  // only on the server are kept (they arrive via the same pull). The imported
  // wrapped-key record is marked dirty too, but the pull-first ordering lets an
  // existing server meta win, so a restore of the same vault never reverts a
  // password change made elsewhere; only an empty server gets seeded from it.
  //
  // Resolves to { entries, vaultId }: vaultId is the namespace recorded in the
  // file (v2 backups; "" for older ones). The caller adopts it (Sync.setVaultId)
  // so the restored device reattaches to the same server vault and the rebase
  // above happens against that vault's live state.
  function importVault(text) {
    var doc;
    try {
      doc = JSON.parse(text);
    } catch (e) {
      return Promise.reject(new Error("not a valid backup file"));
    }
    if (!doc || doc.magic !== EXPORT_MAGIC || !doc.meta) {
      return Promise.reject(new Error("not an Own Vault backup"));
    }
    // The whole decode runs inside try/catch: b64decode (atob) throws
    // synchronously on a truncated/corrupted file, and this function's
    // callers only handle rejections. docToMeta is the single copy of the
    // KDF-bounds check (a hostile backup file is an ingestion point too).
    var record, envs;
    try {
      record = docToMeta(doc.meta);
      record.rev = 0;
      record.dirty = true;
      envs = (doc.entries || []).map(function (e) {
        return {
          id: e.id,
          iv: e.iv ? b64decode(e.iv) : null,
          ciphertext: e.ciphertext ? b64decode(e.ciphertext) : null,
          updatedAt: e.updatedAt,
          deleted: !!e.deleted,
          rev: 0,
          dirty: true,
          restored: true, // authoritative: wins over the server on next sync
          conflict: false,
          remote: null
        };
      });
    } catch (e) {
      return Promise.reject(new Error("backup file is invalid or corrupted"));
    }
    lock();
    // Full reconcile next sync: forget the cursor so the pull returns the whole
    // server state to rebase against and to pick up server-only entries.
    setCursor(0);
    return openDB().then(function (d) {
      return new Promise(function (resolve, reject) {
        var t = d.transaction([STORE_META, STORE_ENTRIES], "readwrite");
        t.objectStore(STORE_META).put(record, META_KEY);
        var es = t.objectStore(STORE_ENTRIES);
        es.clear();
        envs.forEach(function (env) {
          es.put(env);
        });
        t.oncomplete = function () {
          notifyChanged(true);
          resolve({ entries: envs.length, vaultId: doc.vaultId || "" });
        };
        t.onerror = function () {
          reject(t.error);
        };
        t.onabort = function () {
          reject(t.error);
        };
      });
    });
  }

  function onChange(cb) {
    changeCb = cb;
  }

  /* ==================== sync support ==================== */
  // These operate on raw envelopes and speak base64 over the wire, so the
  // sync engine (sync.js) never has to touch binary or crypto. The server
  // only ever sees ciphertext + server-assigned revs.

  var CURSOR_KEY = "syncCursor"; // not secret: highest server rev pulled

  function getCursor() {
    try {
      return parseInt(localStorage.getItem(CURSOR_KEY), 10) || 0;
    } catch (e) {
      return 0;
    }
  }

  function setCursor(rev) {
    try {
      localStorage.setItem(CURSOR_KEY, String(rev || 0));
    } catch (e) {
      /* ignore */
    }
  }

  function envToDTO(env) {
    return {
      id: env.id,
      iv: env.iv ? b64encode(env.iv) : "",
      ciphertext: env.ciphertext ? b64encode(env.ciphertext) : "",
      updatedAt: env.updatedAt,
      deleted: !!env.deleted,
      rev: env.rev || 0
    };
  }

  function dtoToEnv(dto) {
    return {
      id: dto.id,
      iv: dto.iv ? b64decode(dto.iv) : null,
      ciphertext: dto.ciphertext ? b64decode(dto.ciphertext) : null,
      updatedAt: dto.updatedAt,
      deleted: !!dto.deleted,
      rev: dto.rev || 0
    };
  }

  // Dirty, non-conflicted entries to push, each tagged with its base rev.
  function pendingPush() {
    return entriesGetAll().then(function (envs) {
      return envs
        .filter(function (e) {
          return e.dirty && !e.conflict;
        })
        .map(function (e) {
          var dto = envToDTO(e);
          dto.base = e.rev || 0;
          return dto;
        });
    });
  }

  // Apply push results: ok -> clean at the new rev; conflict -> stash the
  // server's version for the user to resolve (local edit stays dirty).
  function confirmPushed(results) {
    return Promise.all(
      (results || []).map(function (res) {
        return entryGetRaw(res.id).then(function (env) {
          if (!env) return;
          if (res.status === "ok") {
            env.rev = res.rev;
            env.dirty = false;
            env.conflict = false;
            env.remote = null;
            env.restored = false;
          } else if (res.status === "conflict") {
            env.conflict = true;
            env.remote = res.server || null;
          }
          return entryPutRaw(env);
        });
      })
    ).then(notifyChanged);
  }

  // Merge pulled remote entries. Silent unless the same entry is dirty locally
  // against a different base rev, which becomes a conflict.
  function applyPulled(remoteDTOs) {
    return entriesGetAll().then(function (envs) {
      // Null prototype: entry ids are server-supplied strings, so a plain {}
      // would let an id like "__proto__" clobber the map's prototype.
      var byId = Object.create(null);
      envs.forEach(function (e) {
        byId[e.id] = e;
      });
      var ops = (remoteDTOs || []).map(function (dto) {
        var local = byId[dto.id];
        if (!local) {
          var fresh = dtoToEnv(dto);
          fresh.dirty = false;
          fresh.conflict = false;
          fresh.remote = null;
          return entryPutRaw(fresh);
        }
        if (!local.dirty) {
          if ((dto.rev || 0) <= (local.rev || 0)) return Promise.resolve();
          var upd = dtoToEnv(dto);
          upd.dirty = false;
          upd.conflict = false;
          upd.remote = null;
          return entryPutRaw(upd);
        }
        // Authoritative restore: adopt the server's rev as our base and keep
        // the backup's value, so the follow-up push is accepted and the backup
        // wins — no conflict is raised.
        if (local.restored) {
          local.rev = dto.rev || 0;
          return entryPutRaw(local);
        }
        // local is a pending local edit
        if ((dto.rev || 0) === (local.rev || 0)) return Promise.resolve();
        // The vault settings record (name) must never surface as a user
        // conflict — auto-merge last-writer-wins by updatedAt.
        if (local.id === SETTINGS_ID) {
          if ((dto.updatedAt || 0) > (local.updatedAt || 0)) {
            var take = dtoToEnv(dto);
            take.dirty = false;
            take.conflict = false;
            take.remote = null;
            return entryPutRaw(take);
          }
          local.rev = dto.rev || 0; // rebase so our newer name pushes and wins
          return entryPutRaw(local);
        }
        local.conflict = true;
        local.remote = dto;
        return entryPutRaw(local);
      });
      return Promise.all(ops).then(notifyChanged);
    });
  }

  function metaToDoc(record) {
    return {
      v: record.v,
      salt: b64encode(record.salt),
      iterations: record.iterations,
      wrapIv: b64encode(record.wrapIv),
      wrapped: b64encode(record.wrapped)
    };
  }

  function docToMeta(doc) {
    // Refuse a hostile/corrupt wrapped-key record at ingestion, before it can
    // replace a good local one (an absurd iteration count would otherwise
    // hang every subsequent unlock attempt).
    if (!validIterations(doc.iterations)) {
      throw new Error("rejected wrapped-key record: bad iteration count");
    }
    return {
      v: doc.v || 1,
      salt: b64decode(doc.salt),
      iterations: doc.iterations,
      wrapIv: b64decode(doc.wrapIv),
      wrapped: b64decode(doc.wrapped)
    };
  }

  // The wrapped-key record to push if it hasn't been synced yet, else null.
  function pendingMeta() {
    return metaGet().then(function (r) {
      return r && r.dirty ? metaToDoc(r) : null;
    });
  }

  function confirmMetaPushed(rev) {
    return metaGet().then(function (r) {
      if (!r) return;
      r.rev = rev;
      r.dirty = false;
      return metaPut(r);
    });
  }

  // Install a wrapped-key record pulled from the server (fresh-device
  // bootstrap, or a password change made on another device).
  function applyMeta(doc, rev) {
    var rec = docToMeta(doc);
    rec.rev = rev;
    rec.dirty = false;
    return metaPut(rec);
  }

  function conflictCount() {
    return entriesGetAll().then(function (envs) {
      return envs.filter(function (e) {
        return e.conflict && e.id !== SETTINGS_ID;
      }).length;
    });
  }

  // Decrypted mine/theirs pairs for every unresolved conflict.
  function listConflicts() {
    requireUnlocked();
    return entriesGetAll().then(function (envs) {
      var conflicted = envs.filter(function (e) {
        return e.conflict && e.remote && e.id !== SETTINGS_ID;
      });
      return Promise.all(
        conflicted.map(function (e) {
          var mineP = e.deleted
            ? Promise.resolve({ deleted: true })
            : decryptEnvelope(e).catch(function () {
                return null;
              });
          var remoteEnv = dtoToEnv(e.remote);
          var theirsP = remoteEnv.deleted
            ? Promise.resolve({ deleted: true })
            : decryptForEntry(e.id, remoteEnv.iv, remoteEnv.ciphertext)
                .then(function (b) {
                  return JSON.parse(utf8Decode(b));
                })
                .catch(function () {
                  return null;
                });
          return Promise.all([mineP, theirsP]).then(function (r) {
            return { id: e.id, mine: r[0], theirs: r[1] };
          });
        })
      );
    });
  }

  // keep = "mine" rebases the local edit onto the server's rev so the next
  // push is accepted; keep = "theirs" takes the server version verbatim.
  function resolveConflict(id, keep) {
    requireUnlocked();
    return entryGetRaw(id).then(function (env) {
      if (!env || !env.conflict) return;
      var remoteRev = env.remote ? env.remote.rev || 0 : env.rev || 0;
      if (keep === "theirs") {
        var upd = dtoToEnv(env.remote);
        upd.dirty = false;
        upd.conflict = false;
        upd.remote = null;
        return entryPutRaw(upd).then(notifyChanged);
      }
      env.rev = remoteRev;
      env.dirty = true;
      env.conflict = false;
      env.remote = null;
      return entryPutRaw(env).then(notifyChanged);
    });
  }

  return {
    isInitialized: isInitialized,
    isUnlocked: isUnlocked,
    create: create,
    unlock: unlock,
    lock: lock,
    changePassword: changePassword,
    list: list,
    get: get,
    put: put,
    putMany: putMany,
    parseCSV: parseCSV,
    remove: remove,
    getName: getName,
    setName: setName,
    exportVault: exportVault,
    importVault: importVault,
    onChange: onChange,
    // sync
    getCursor: getCursor,
    setCursor: setCursor,
    pendingPush: pendingPush,
    confirmPushed: confirmPushed,
    applyPulled: applyPulled,
    pendingMeta: pendingMeta,
    confirmMetaPushed: confirmMetaPushed,
    applyMeta: applyMeta,
    conflictCount: conflictCount,
    listConflicts: listConflicts,
    resolveConflict: resolveConflict
  };
})();
