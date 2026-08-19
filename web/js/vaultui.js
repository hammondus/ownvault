/*
 * Own Vault — UI glue between the DOM and the DOM-free Vault core.
 *
 * Owns: the lock gate (first-run / unlock overlay), auto-lock, the passwords
 * list + live search, the record modal (view / add / edit / delete), copy
 * icons with clipboard auto-wipe, and the reveal toggle. All vault crypto and
 * storage lives in vault.js; this file never touches keys or ciphertext.
 *
 * Screen fragments are swapped by htmx, so passwords-screen controls are bound
 * via delegation on #main. The lock overlay and modal are persistent chrome in
 * index.html and are bound directly.
 */
(function () {
  "use strict";

  var AUTO_LOCK_MS = 5 * 60 * 1000; // re-lock after this much inactivity
  var CLIP_CLEAR_KEY = "clipClearSecs"; // localStorage: password clipboard wipe delay
  var CLIP_CLEAR_DEFAULT = 20; // seconds; 0 = never wipe

  function clipClearMs() {
    var secs = CLIP_CLEAR_DEFAULT;
    try {
      var raw = localStorage.getItem(CLIP_CLEAR_KEY);
      if (raw !== null && raw !== "") secs = parseInt(raw, 10);
    } catch (e) {
      /* ignore */
    }
    if (isNaN(secs) || secs < 0) secs = CLIP_CLEAR_DEFAULT;
    return secs * 1000;
  }

  var entries = []; // decrypted cache, refreshed on unlock and on change
  var searchTerm = "";
  var idleTimer = null;
  var clipTimer = null;

  /* ==================== PWA install ==================== */
  // Chromium fires beforeinstallprompt when the app is installable; we stash the
  // event so the welcome step can offer an explicit "Install app" button (the
  // browser's own control is easy to miss). iOS Safari has no such API, so it
  // gets manual Add-to-Home-Screen steps instead. See updateInstallUI.
  var deferredInstallPrompt = null;

  function isStandalone() {
    return (
      (window.matchMedia &&
        window.matchMedia("(display-mode: standalone)").matches) ||
      window.navigator.standalone === true
    );
  }

  function isIOS() {
    var ua = window.navigator.userAgent || "";
    // iPadOS 13+ presents as a Mac, so also treat a touch-capable "Macintosh"
    // as iOS.
    return (
      /iPad|iPhone|iPod/.test(ua) ||
      (/Macintosh/.test(ua) && window.navigator.maxTouchPoints > 1)
    );
  }

  window.addEventListener("beforeinstallprompt", function (e) {
    e.preventDefault(); // keep the mini-infobar from showing; we drive it ourselves
    deferredInstallPrompt = e;
    updateInstallUI();
  });

  window.addEventListener("appinstalled", function () {
    deferredInstallPrompt = null;
    updateInstallUI();
  });

  // Decide what (if anything) each install area shows. Drives every
  // `.install-block` on the page — the welcome step and the Settings card — so
  // both stay in step. Each block holds an `.install-btn` (native prompt), an
  // `.install-ios` (manual Add-to-Home-Screen steps), and optionally an
  // `.install-done` (already-installed note). Called when a block appears
  // (welcome step / Settings swap) and whenever install state changes.
  function updateInstallUI() {
    var blocks = document.querySelectorAll(".install-block");
    var installed = isStandalone();
    for (var i = 0; i < blocks.length; i++) {
      var block = blocks[i];
      var btn = block.querySelector(".install-btn");
      var ios = block.querySelector(".install-ios");
      var done = block.querySelector(".install-done");
      var visible;
      if (installed) {
        // Already running as an installed app: only blocks with a "done" note
        // (Settings) stay, to confirm it; the welcome block just disappears.
        show(btn, false);
        show(ios, false);
        show(done, true);
        visible = !!done;
      } else if (deferredInstallPrompt) {
        show(done, false);
        show(ios, false);
        show(btn, true);
        visible = true;
      } else if (isIOS()) {
        show(done, false);
        show(btn, false);
        show(ios, true);
        visible = true;
      } else {
        // Not installable (yet): the event may not have fired, or the browser
        // can't install. Hide the block; it re-appears if the event arrives.
        visible = false;
      }
      block.hidden = !visible;
      // In Settings each block lives in its own card — hide the whole card when
      // there's nothing to show. The welcome block isn't in a `.card`.
      var card = block.closest(".card");
      if (card) card.hidden = !visible;
    }
  }

  /* ==================== tiny DOM helper ==================== */

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        // Deliberately no innerHTML branch: everything renders via textContent
        // so vault data can never be interpreted as markup.
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c) node.appendChild(c);
    });
    return node;
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function show(node, on) {
    if (node) node.hidden = !on;
  }

  // WebCrypto (crypto.subtle) only exists in a secure context. Plain HTTP to a
  // LAN IP — the usual way people first hit the app from a phone — is NOT secure,
  // so subtle is undefined and every unlock/create would throw deep in the crypto
  // chain. Detect it up front and explain, instead of failing silently.
  // (localhost is a secure-context exception, which is why desktop dev works.)
  function webCryptoReady() {
    return !!(window.crypto && window.crypto.subtle);
  }

  var INSECURE_MSG =
    "This device needs a secure (HTTPS) connection to unlock — browser " +
    "encryption is turned off otherwise. Open Own Vault at its https:// address " +
    "(on a phone over your LAN, use the server's HTTPS URL — see the README's " +
    "mkcert / iPhone setup).";

  /* ==================== lock gate ==================== */

  function showLock(mode) {
    document.body.classList.add("locked");
    show(byId("lock-screen"), true);
    show(byId("create-form"), mode === "create");
    show(byId("unlock-form"), mode === "unlock");
    show(byId("connect-form"), mode === "connect");
    show(byId("welcome-panel"), mode === "welcome");
    show(byId("create-error"), false);
    show(byId("unlock-error"), false);
    show(byId("connect-error"), false);
    show(byId("restore-msg"), false);
    // The welcome step surfaces the freshly created vault's id (sync vaults
    // only) and offers to install the app.
    if (mode === "welcome") {
      var syncing = !!(window.Sync && Sync.isEnabled());
      show(byId("welcome-sync"), syncing);
      show(byId("welcome-offline-lead"), !syncing);
      var wid = byId("welcome-vault-id");
      if (wid) wid.value = syncing ? Sync.getVaultId() : "";
      var wname = byId("welcome-name");
      var vname = window.App ? App.getVaultName() : "";
      if (wname) {
        wname.textContent = vname ? "“" + vname + "” is ready" : "";
        show(wname, !!vname);
      }
      updateInstallUI();
    }
    // Start the connect fields empty. The Vault ID must be the *other* device's
    // vault (copied from its Settings) — never this device's own local id, which
    // would just fail to find anything and confuse.
    ["create-name", "create-pw", "create-pw2", "unlock-pw", "connect-id", "connect-token"].forEach(function (id) {
      var f = byId(id);
      if (f) f.value = "";
    });
    var focusId =
      mode === "create" ? "create-pw"
        : mode === "connect" ? "connect-id"
        : mode === "welcome" ? "welcome-continue"
        : "unlock-pw";
    var focus = byId(focusId);
    if (focus) {
      setTimeout(function () {
        focus.focus();
      }, 50);
    }
    // Surface the insecure-context problem immediately (before a dead tap on a
    // form that can't possibly work). Connect only reaches the server, so it's
    // fine without WebCrypto; the message belongs on create/unlock.
    if (!webCryptoReady() && (mode === "create" || mode === "unlock")) {
      var ie = byId(mode === "create" ? "create-error" : "unlock-error");
      if (ie) {
        ie.textContent = INSECURE_MSG;
        show(ie, true);
      }
    }
  }

  function hideLock() {
    document.body.classList.remove("locked");
    show(byId("lock-screen"), false);
  }

  function startGate() {
    Vault.isInitialized().then(function (exists) {
      if (exists) {
        showLock("unlock");
        return;
      }
      // Fresh device. With namespacing there is no single "the vault" to find,
      // so we can't silently bootstrap — the user either supplies an existing
      // Vault ID (connect) or starts a new vault. Offline vaults skip straight
      // to create.
      if (window.Sync && Sync.isEnabled()) {
        showLock("connect");
      } else {
        showLock("create");
      }
    });
  }

  // Connect this device to an existing vault: store its id (+ token), then pull.
  // Success (server had that vault's wrapped-key record) routes to unlock; a bad
  // token or unknown id reports inline so the user can fix it.
  function handleConnect(e) {
    e.preventDefault();
    var err = byId("connect-error");
    if (!window.Sync) {
      showLock("create");
      return;
    }
    var id = byId("connect-id").value.trim();
    if (!id) {
      err.textContent = "Enter your Vault ID, or start a new vault.";
      show(err, true);
      return;
    }
    Sync.setToken(byId("connect-token").value.trim());
    Sync.setVaultId(id);
    Sync.bootstrap().then(function (res) {
      if (res.exists) {
        // The vault name is inherited from the vault itself on first unlock
        // (reconcileVaultName), so there's nothing to ask for here.
        showLock("unlock");
      } else if (res.needsAuth) {
        err.textContent = "Access token required or incorrect.";
        show(err, true);
      } else {
        err.textContent =
          "No vault with that ID on this server. Check the ID, or start a new vault.";
        show(err, true);
      }
    });
  }

  // "Start a new vault instead": keep any token the user typed (a shared server
  // may require it even to create), mint a fresh namespace, and collect a master
  // password.
  function handleConnectCreate() {
    if (window.Sync) {
      Sync.setToken(byId("connect-token").value.trim());
      Sync.setVaultId(Sync.newVaultId());
    }
    showLock("create");
  }

  // "Use offline only": no server at all. Disable sync so we never push, and
  // still mint an id so enabling sync later just works.
  function handleConnectOffline() {
    if (window.Sync) {
      Sync.setEnabled(false);
      Sync.ensureVaultId();
    }
    showLock("create");
  }

  // Recovery path from the lock gate (no vault to unlock yet): pick an encrypted
  // backup file, restore it, and adopt the vault id it records so the device
  // reattaches to that server namespace. Then unlock with the backup's password.
  function openRestore() {
    var f = byId("restore-file");
    if (f) f.click();
  }

  function handleRestoreFile(e) {
    var file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    var msg = byId("restore-msg");
    var reader = new FileReader();
    reader.onload = function () {
      Vault.importVault(String(reader.result)).then(
        function (res) {
          if (res.vaultId && window.Sync) Sync.setVaultId(res.vaultId);
          // Backup restored -> a vault now exists locally; unlock with its
          // master password. showLock clears the restore message.
          showLock("unlock");
        },
        function (err) {
          if (msg) {
            msg.textContent = (err && err.message) || "Couldn't read that backup.";
            show(msg, true);
          }
        }
      );
    };
    reader.readAsText(file);
  }

  function afterUnlock() {
    hideLock();
    resetIdle();
    loadEntries();
    if (window.Sync) Sync.start();
    refreshConflicts();
    reconcileVaultName();
  }

  // The vault name is both the installed-app name (App, in app.js — local +
  // manifest) and an encrypted, synced vault setting (Vault) so other devices
  // inherit it. Setting it writes both; reconciling adopts whatever the vault
  // carries (how a freshly connected device inherits the name), or seeds the
  // vault from a pre-existing local-only name.
  function persistVaultName(name) {
    if (window.App) App.setVaultName(name); // local display + PWA manifest
    if (Vault.isUnlocked()) return Vault.setName(name); // encrypted + synced
    return Promise.resolve();
  }

  function reconcileVaultName() {
    if (!Vault.isUnlocked() || !window.App) return;
    Vault.getName().then(function (vname) {
      var local = App.getVaultName();
      if (vname) {
        // The vault carries the canonical name -> adopt it locally. This is how
        // a freshly connected device inherits the name. Never writes back.
        if (local !== vname) App.setVaultName(vname);
      } else if (local) {
        // Pre-existing local-only name (older vault, or the device that created
        // it before the name was synced) -> seed the vault so it propagates.
        Vault.setName(local);
      }
    });
  }

  function handleCreate(e) {
    e.preventDefault();
    var pw = byId("create-pw").value;
    var pw2 = byId("create-pw2").value;
    var err = byId("create-error");
    if (!webCryptoReady()) {
      err.textContent = INSECURE_MSG;
      show(err, true);
      return;
    }
    // 12-char floor: the vault is offline-brute-forceable from a stolen
    // backup or server DB, so the master password carries the whole load —
    // PBKDF2 alone can't rescue a short one.
    if (pw.length < 12) {
      err.textContent =
        "Use at least 12 characters — a few random words make a strong passphrase.";
      show(err, true);
      return;
    }
    if (pw !== pw2) {
      err.textContent = "The two passwords don't match.";
      show(err, true);
      return;
    }
    // Every new vault gets its own server namespace (safety net for the offline
    // path that reaches create directly; the connect screen sets one already).
    if (window.Sync) Sync.ensureVaultId();
    var name = byId("create-name").value.trim();
    Vault.create(pw).then(function () {
      // Adopt the vault name: labels the installed app icon + lock screen (App)
      // and stores it as an encrypted, synced setting (Vault) so other devices
      // inherit it. Applied before the welcome step so the install button there
      // already advertises the chosen name in the manifest.
      if (name) persistVaultName(name);
      // Show the welcome step: it surfaces the Vault ID (sync vaults only, so
      // other devices can connect — offline vaults have no server yet, and it's
      // always in Settings later) and offers to install the app.
      showLock("welcome");
    }, function () {
      err.textContent = "Couldn't create the vault.";
      show(err, true);
    });
  }

  function handleUnlock(e) {
    e.preventDefault();
    var err = byId("unlock-error");
    if (!webCryptoReady()) {
      err.textContent = INSECURE_MSG;
      show(err, true);
      return;
    }
    var pw = byId("unlock-pw").value;
    Vault.unlock(pw).then(
      function (ok) {
        if (ok) {
          // Clear immediately — showLock only wipes fields on the *next* lock,
          // which would leave the master password sitting in the DOM (readable
          // by any script or devtools snapshot) for the whole session.
          byId("unlock-pw").value = "";
          afterUnlock();
        } else {
          err.textContent = "Incorrect master password.";
          show(err, true);
          byId("unlock-pw").select();
        }
      },
      function () {
        // Never leave the button dead: surface the failure instead of the old
        // silent unhandled-rejection (which is what iOS-over-HTTP hit).
        err.textContent = webCryptoReady()
          ? "Couldn't unlock — an unexpected error occurred."
          : INSECURE_MSG;
        show(err, true);
      }
    );
  }

  function lockNow() {
    Vault.lock();
    if (window.Sync) Sync.stop();
    entries = [];
    searchTerm = "";
    closeModal();
    closeConflictModal();
    clearRecoverySheet(); // never leave printed plaintext in the DOM past a lock
    var list = byId("pw-list");
    if (list) list.innerHTML = "";
    showConflictBanner(0);
    clearTimeout(idleTimer);
    showLock("unlock");
  }

  /* ==================== auto-lock ==================== */

  var lastActivity = Date.now();

  function resetIdle() {
    if (!Vault.isUnlocked()) return;
    lastActivity = Date.now();
    clearTimeout(idleTimer);
    idleTimer = setTimeout(lockNow, AUTO_LOCK_MS);
  }

  ["pointerdown", "keydown"].forEach(function (evt) {
    document.addEventListener(evt, function () {
      if (Vault.isUnlocked()) resetIdle();
    });
  });

  // Browsers suspend timers in background tabs (and mobile OSes freeze the
  // page outright), so the idle timer alone can leave the vault unlocked long
  // past its deadline. On return to the foreground, lock immediately if the
  // inactivity window has already passed.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    if (Vault.isUnlocked() && Date.now() - lastActivity > AUTO_LOCK_MS) {
      lockNow();
    }
  });

  /* ==================== list + search ==================== */

  function loadEntries() {
    if (!Vault.isUnlocked()) return;
    Vault.list().then(function (rows) {
      entries = rows.sort(function (a, b) {
        return (a.title || "").localeCompare(b.title || "");
      });
      renderList();
    });
  }

  function matches(entry, term) {
    if (!term) return true;
    // Per spec: search spans every field, including password and notes, even
    // though only title/username/url are displayed.
    var hay = [
      entry.title,
      entry.username,
      entry.url,
      entry.password,
      entry.notes
    ]
      .join("\n")
      .toLowerCase();
    return hay.indexOf(term) !== -1;
  }

  function renderList() {
    var list = byId("pw-list");
    var empty = byId("pw-empty");
    if (!list) return;
    list.innerHTML = "";

    var shown = entries.filter(function (e) {
      return matches(e, searchTerm);
    });

    if (!entries.length) {
      empty.textContent = "No passwords yet. Tap + to add one.";
      show(empty, true);
    } else if (!shown.length) {
      empty.textContent = "No matches.";
      show(empty, true);
    } else {
      show(empty, false);
    }

    shown.forEach(function (e) {
      var meta = [e.username, e.url].filter(Boolean).join("  •  ");
      var titleNode = el("div", { class: "pw-item-title", text: e.title || "(untitled)" });
      if (e.critical) {
        titleNode.appendChild(el("span", { class: "pw-badge pw-badge-critical", text: "critical" }));
      }
      if (e.conflict) {
        titleNode.appendChild(el("span", { class: "pw-badge", text: "conflict" }));
      }
      var row = el("li", {
        class: "pw-item" + (e.conflict ? " pw-item-conflict" : ""),
        "data-id": e.id,
        tabindex: "0"
      }, [titleNode, meta ? el("div", { class: "pw-item-sub", text: meta }) : null]);
      list.appendChild(row);
    });
  }

  /* ==================== record modal ==================== */

  function copyRow(labelText, value, kind) {
    var isPassword = kind === "password";
    var isUrl = kind === "url";
    var valNode = el("span", {
      class: "field-value" + (isPassword ? " masked" : ""),
      text: value || ""
    });
    if (isPassword) valNode.dataset.real = value || "";

    var actions = [];
    if (isPassword) {
      actions.push(
        el("button", {
          class: "icon-btn",
          type: "button",
          "data-reveal": "1",
          "aria-label": "Show password",
          text: "👁"
        })
      );
    }
    if (isUrl) {
      actions.push(
        el("button", {
          class: "icon-btn",
          type: "button",
          "data-open": "1",
          "aria-label": "Open URL in a new tab",
          text: "↗"
        })
      );
    }
    actions.push(
      el("button", {
        class: "icon-btn",
        type: "button",
        "data-copy": isPassword ? "password" : "1",
        "aria-label": "Copy " + labelText,
        text: "⧉"
      })
    );

    return el("div", { class: "field" }, [
      el("div", { class: "field-label", text: labelText }),
      el("div", { class: "field-body" }, [valNode].concat(actions))
    ]);
  }

  function textField(labelText, value) {
    if (!value) return null;
    return el("div", { class: "field" }, [
      el("div", { class: "field-label", text: labelText }),
      el("div", { class: "field-body" }, [
        el("span", { class: "field-value", text: value })
      ])
    ]);
  }

  function openModalView(entry) {
    var card = byId("modal-card");
    card.innerHTML = "";
    card.dataset.mode = "view";
    card.dataset.id = entry.id;

    var when =
      "Modified " + new Date(entry.modified || entry.updatedAt).toLocaleString();

    var title = el("h2", { class: "modal-title", text: entry.title || "(untitled)" });
    if (entry.critical) {
      title.appendChild(el("span", { class: "pw-badge pw-badge-critical", text: "critical" }));
    }
    card.appendChild(
      el("div", { class: "modal-head" }, [
        title,
        el("button", {
          class: "icon-btn modal-close",
          type: "button",
          "data-close": "1",
          "aria-label": "Close",
          text: "✕"
        })
      ])
    );

    var body = el("div", { class: "modal-body" }, [
      entry.username ? copyRow("Username", entry.username, "text") : null,
      entry.password ? copyRow("Password", entry.password, "password") : null,
      entry.url ? copyRow("URL", entry.url, "url") : null,
      textField("Notes", entry.notes),
      el("div", { class: "field-when", text: when })
    ]);
    card.appendChild(body);

    card.appendChild(
      el("div", { class: "modal-foot" }, [
        el("button", {
          class: "btn btn-danger",
          type: "button",
          "data-delete": "1",
          text: "Delete"
        }),
        el("button", {
          class: "btn",
          type: "button",
          "data-edit": "1",
          text: "Edit"
        })
      ])
    );

    openModal();
  }

  // spellcheck/autocorrect off on every field: Chromium's "enhanced
  // spellcheck" transmits field contents to a cloud service, and usernames,
  // URLs, and notes in a password vault must never take that trip.
  function inputField(name, labelText, value, type) {
    var input = el("input", {
      class: "form-input",
      type: type || "text",
      name: name,
      autocomplete: "off",
      spellcheck: "false",
      autocorrect: "off",
      autocapitalize: "off",
      value: value || ""
    });
    return el("label", { class: "form-row" }, [
      el("span", { class: "form-label", text: labelText }),
      input
    ]);
  }

  // The password is masked against shoulder surfing with the same CSS the
  // view modal uses (-webkit-text-security on a type="text" input) rather
  // than type="password": browser save-password/autofill heuristics key on
  // the input type, and a real password field here would invite the browser
  // to capture vault entries into its own (cloud-synced) password store.
  function passwordField(value) {
    var input = el("input", {
      class: "form-input masked",
      type: "text",
      name: "password",
      autocomplete: "off",
      spellcheck: "false",
      autocorrect: "off",
      autocapitalize: "off",
      value: value || ""
    });
    var toggle = el("button", {
      class: "icon-btn",
      type: "button",
      "data-reveal-input": "1",
      "aria-label": "Show password",
      text: "👁"
    });
    return el("div", { class: "form-row" }, [
      el("span", { class: "form-label", text: "Password" }),
      el("div", { class: "sync-row" }, [input, toggle])
    ]);
  }

  function openModalEdit(entry) {
    entry = entry || {};
    var card = byId("modal-card");
    card.innerHTML = "";
    card.dataset.mode = "edit";
    card.dataset.id = entry.id || "";

    card.appendChild(
      el("div", { class: "modal-head" }, [
        el("h2", {
          class: "modal-title",
          text: entry.id ? "Edit entry" : "New entry"
        }),
        el("button", {
          class: "icon-btn modal-close",
          type: "button",
          "data-close": "1",
          "aria-label": "Close",
          text: "✕"
        })
      ])
    );

    var notes = el("textarea", {
      class: "form-input",
      name: "notes",
      rows: "3",
      spellcheck: "false",
      autocorrect: "off",
      autocapitalize: "off"
    });
    notes.value = entry.notes || "";

    var criticalInput = el("input", { type: "checkbox", name: "critical", class: "form-check-input" });
    criticalInput.checked = !!entry.critical;
    var criticalRow = el("label", { class: "form-check" }, [
      criticalInput,
      el("span", { class: "form-check-label", text: "Critical — include on the printed emergency recovery sheet" })
    ]);

    // novalidate: the url field pre-fills a bare "https://" that native
    // type=url validation would reject and silently block submission on; we
    // normalise the url ourselves in saveFromForm.
    var form = el("form", { id: "record-form", class: "modal-body", novalidate: "novalidate" }, [
      inputField("title", "Title", entry.title, "text"),
      inputField("username", "Username", entry.username, "text"),
      passwordField(entry.password),
      // Pre-fill the scheme on new entries to save typing; a bare scheme is
      // treated as empty on save.
      inputField("url", "URL", entry.id ? entry.url : entry.url || "https://", "url"),
      el("label", { class: "form-row" }, [
        el("span", { class: "form-label", text: "Notes" }),
        notes
      ]),
      criticalRow
    ]);
    card.appendChild(form);

    card.appendChild(
      el("div", { class: "modal-foot" }, [
        el("button", {
          class: "btn btn-ghost",
          type: "button",
          "data-close": "1",
          text: "Cancel"
        }),
        el("button", {
          class: "btn",
          type: "submit",
          form: "record-form",
          text: "Save"
        })
      ])
    );

    openModal();
    setTimeout(function () {
      var t = form.querySelector('input[name="title"]');
      if (t) t.focus();
    }, 50);
  }

  function saveFromForm(e) {
    e.preventDefault();
    var card = byId("modal-card");
    var form = byId("record-form");
    var id = card.dataset.id || null;
    var existing = id
      ? entries.filter(function (x) {
          return x.id === id;
        })[0]
      : null;
    var url = form.url.value.trim();
    if (url === "https://" || url === "http://") url = "";
    var fields = {
      id: id || undefined,
      created: existing ? existing.created : undefined,
      title: form.title.value.trim(),
      username: form.username.value.trim(),
      password: form.password.value,
      url: url,
      notes: form.notes.value,
      critical: form.critical.checked
    };
    Vault.put(fields).then(function () {
      closeModal();
      // onChange -> loadEntries re-renders the list.
    });
  }

  function deleteCurrent() {
    var card = byId("modal-card");
    var id = card.dataset.id;
    if (!id) return;
    var match = entries.filter(function (x) {
      return x.id === id;
    })[0];
    var title = match && match.title ? match.title : "this entry";
    confirmDialog({
      title: "Delete entry?",
      message: "“" + title + "” will be permanently deleted. This can't be undone.",
      confirmText: "Delete",
      danger: true
    }).then(function (ok) {
      if (ok) Vault.remove(id).then(closeModal);
    });
  }

  function openModal() {
    show(byId("record-modal"), true);
    document.body.classList.add("modal-open");
  }

  function closeModal() {
    var m = byId("record-modal");
    if (m && !m.hidden) {
      m.hidden = true;
      byId("modal-card").innerHTML = "";
    }
    if (byId("confirm-modal").hidden) document.body.classList.remove("modal-open");
  }

  /* ==================== confirm dialog ==================== */
  // In-app replacement for window.confirm() so destructive prompts match the
  // app's modal styling instead of the browser's chrome. Returns a promise that
  // resolves true (confirmed) / false (cancelled). Layers above the record and
  // conflict modals. opts: { title, message, confirmText, danger }.

  var confirmResolve = null;

  function confirmDialog(opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      // A second confirm shouldn't strand the first: resolve it as cancelled.
      if (confirmResolve) confirmResolve(false);
      confirmResolve = resolve;
      byId("confirm-title").textContent = opts.title || "Are you sure?";
      byId("confirm-text").textContent = opts.message || "";
      var ok = byId("confirm-ok");
      ok.textContent = opts.confirmText || "Confirm";
      ok.className = opts.danger ? "btn btn-danger" : "btn";
      show(byId("confirm-modal"), true);
      document.body.classList.add("modal-open");
      setTimeout(function () {
        ok.focus();
      }, 50);
    });
  }

  function closeConfirm(result) {
    var m = byId("confirm-modal");
    if (m && !m.hidden) m.hidden = true;
    // Keep modal-open set if a modal is still open underneath this one.
    if (byId("record-modal").hidden && byId("conflict-modal").hidden) {
      document.body.classList.remove("modal-open");
    }
    var resolve = confirmResolve;
    confirmResolve = null;
    if (resolve) resolve(!!result);
  }

  /* ==================== clipboard ==================== */

  function copyValue(value, isPassword) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(value).then(function () {
      var ms = clipClearMs();
      if (isPassword && ms > 0) {
        toast("Password copied — clears in " + ms / 1000 + "s");
        clearTimeout(clipTimer);
        clipTimer = setTimeout(function () {
          // Best effort: overwrite the clipboard so a copied secret doesn't
          // linger. Can't verify it's still ours without a read prompt.
          navigator.clipboard.writeText("").catch(function () {});
        }, ms);
      } else {
        toast("Copied");
      }
    });
  }

  function toast(msg) {
    var t = byId("toast");
    if (!t) return;
    t.textContent = msg;
    t.classList.add("visible");
    setTimeout(function () {
      t.classList.remove("visible");
    }, 2500);
  }

  /* ==================== event wiring ==================== */

  // Passwords-screen controls (swapped in by htmx) via delegation on #main.
  var mainEl = byId("main");

  mainEl.addEventListener("click", function (e) {
    var add = e.target.closest("#pw-add");
    if (add) {
      openModalEdit(null);
      return;
    }
    var item = e.target.closest(".pw-item");
    if (item) {
      var entry = entries.filter(function (x) {
        return x.id === item.dataset.id;
      })[0];
      if (entry) openModalView(entry);
    }
  });

  mainEl.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    var item = e.target.closest(".pw-item");
    if (item) {
      var entry = entries.filter(function (x) {
        return x.id === item.dataset.id;
      })[0];
      if (entry) openModalView(entry);
    }
  });

  mainEl.addEventListener("input", function (e) {
    if (e.target.id === "pw-search") {
      searchTerm = e.target.value.trim().toLowerCase();
      renderList();
    }
  });

  // Re-render the list whenever the passwords fragment (re)appears.
  document.body.addEventListener("htmx:afterSwap", function () {
    if (byId("passwords-screen") && Vault.isUnlocked()) {
      searchTerm = "";
      renderList();
    }
    syncSettingsControls();
  });
  document.body.addEventListener("htmx:historyRestore", syncSettingsControls);

  // Reflect saved preferences whenever the Settings fragment arrives.
  function syncSettingsControls() {
    var sel = byId("clip-clear-select");
    if (sel) sel.value = String(clipClearMs() / 1000);
    if (window.Sync) {
      var en = byId("sync-enable");
      if (en) en.checked = Sync.isEnabled();
      var tok = byId("sync-token");
      if (tok) tok.value = Sync.getToken();
      var st = byId("sync-status");
      if (st) st.textContent = Sync.getStatus().message || "";
      var vid = byId("vault-id");
      if (vid) vid.value = Sync.getVaultId();
    }
    if (window.App) {
      var vn = byId("vault-name");
      if (vn) vn.value = App.getVaultName();
    }
    updateInstallUI(); // reflect install state in the Settings install card
  }

  // Modal (persistent chrome) via delegation on the modal root.
  var modalEl = byId("record-modal");
  modalEl.addEventListener("click", function (e) {
    if (e.target.closest("[data-close]")) {
      closeModal();
      return;
    }
    if (e.target.closest("[data-edit]")) {
      var id = byId("modal-card").dataset.id;
      var entry = entries.filter(function (x) {
        return x.id === id;
      })[0];
      openModalEdit(entry);
      return;
    }
    if (e.target.closest("[data-delete]")) {
      deleteCurrent();
      return;
    }
    // Edit-form password visibility toggle (flips the CSS mask).
    var revealInput = e.target.closest("[data-reveal-input]");
    if (revealInput) {
      var inp = revealInput.parentNode.querySelector("input");
      if (inp) {
        var showNow = inp.classList.contains("masked");
        inp.classList.toggle("masked", !showNow);
        revealInput.textContent = showNow ? "🙈" : "👁";
        revealInput.setAttribute(
          "aria-label",
          showNow ? "Hide password" : "Show password"
        );
      }
      return;
    }
    var reveal = e.target.closest("[data-reveal]");
    if (reveal) {
      var span = reveal.parentNode.querySelector(".field-value");
      if (span.classList.contains("masked")) {
        span.classList.remove("masked");
        reveal.textContent = "🙈";
      } else {
        span.classList.add("masked");
        reveal.textContent = "👁";
      }
      return;
    }
    var openBtn = e.target.closest("[data-open]");
    if (openBtn) {
      var urlNode = openBtn.parentNode.querySelector(".field-value");
      var href = urlNode.textContent;
      if (href && !/^https?:\/\//i.test(href)) href = "https://" + href;
      if (href) window.open(href, "_blank", "noopener,noreferrer");
      return;
    }
    var copy = e.target.closest("[data-copy]");
    if (copy) {
      var isPw = copy.getAttribute("data-copy") === "password";
      var valNode = copy.parentNode.querySelector(".field-value");
      var value = isPw ? valNode.dataset.real : valNode.textContent;
      copyValue(value, isPw);
    }
  });

  modalEl.addEventListener("submit", function (e) {
    if (e.target.id === "record-form") saveFromForm(e);
  });

  // Lock overlay forms (persistent chrome).
  byId("create-form").addEventListener("submit", handleCreate);
  byId("unlock-form").addEventListener("submit", handleUnlock);
  byId("connect-form").addEventListener("submit", handleConnect);
  byId("connect-create").addEventListener("click", handleConnectCreate);
  byId("connect-offline").addEventListener("click", handleConnectOffline);
  byId("create-restore").addEventListener("click", openRestore);
  byId("connect-restore").addEventListener("click", openRestore);
  byId("restore-file").addEventListener("change", handleRestoreFile);
  byId("welcome-continue").addEventListener("click", afterUnlock);
  byId("welcome-copy").addEventListener("click", function () {
    if (window.Sync) copyValue(Sync.getVaultId(), false);
  });
  // Install button (welcome step + Settings card) — delegated on body so the one
  // handler covers both the persistent welcome chrome and the swapped-in
  // Settings fragment.
  document.body.addEventListener("click", function (e) {
    if (!e.target.closest(".install-btn")) return;
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    // One-shot: the event can't be re-prompted, so drop it and re-render the UI
    // regardless of whether the user accepted or dismissed.
    deferredInstallPrompt.userChoice.then(function () {
      deferredInstallPrompt = null;
      updateInstallUI();
    });
  });

  /* ==================== emergency recovery sheet ==================== */
  // Print the entries the user marked "critical" (crypto seeds, master
  // passwords, 2FA backup codes) onto paper — an offline last resort immune to
  // device failure / ransomware. Rendered into #print-sheet, which a print
  // stylesheet shows in place of the app while body.printing-sheet is set.

  function buildRecoverySheet(list) {
    var sheet = byId("print-sheet");
    if (!sheet) return;
    sheet.innerHTML = "";
    sheet.appendChild(el("h1", { class: "ps-title", text: "Own Vault — Emergency Recovery Sheet" }));
    sheet.appendChild(el("p", { class: "ps-date", text: "Printed " + new Date().toLocaleString() }));
    sheet.appendChild(
      el("p", { class: "ps-warning" }, [
        el("strong", { text: "Keep this paper safe. " }),
        el("span", {
          text:
            "It lists passwords in plain text — anyone holding it can use them " +
            "without your master password. Store it somewhere physically secure " +
            "and destroy old copies."
        })
      ])
    );

    function field(rows, label, val) {
      if (!val) return;
      rows.push(
        el("div", { class: "ps-field" }, [
          el("span", { class: "ps-label", text: label }),
          el("span", { class: "ps-value", text: val })
        ])
      );
    }

    list.forEach(function (e) {
      var rows = [el("h2", { class: "ps-entry-title", text: e.title || "(untitled)" })];
      field(rows, "Username", e.username);
      field(rows, "Password", e.password);
      field(rows, "URL", e.url);
      field(rows, "Notes", e.notes);
      sheet.appendChild(el("div", { class: "ps-entry" }, rows));
    });
  }

  function clearRecoverySheet() {
    document.body.classList.remove("printing-sheet");
    var sheet = byId("print-sheet");
    if (sheet) sheet.innerHTML = ""; // don't leave plaintext secrets in the DOM
  }

  function printRecoverySheet() {
    if (!Vault.isUnlocked()) return;
    var critical = entries.filter(function (e) {
      return e.critical;
    });
    if (!critical.length) {
      settingsMsg(
        "recovery-msg",
        "No entries are marked critical yet. Open an entry, tap Edit, and tick “Critical”.",
        true
      );
      return;
    }
    var warn =
      critical.length + " critical " + (critical.length > 1 ? "entries" : "entry") +
      " will be printed IN PLAIN TEXT, including passwords.\n\n" +
      "• Anyone who holds the paper has these secrets — no master password needed.\n" +
      "• Printers (especially shared / office / networked) can keep a copy of what they print.\n" +
      "• Store the sheet somewhere physically secure and shred it when it's replaced.";
    confirmDialog({
      title: "Print recovery sheet?",
      message: warn,
      confirmText: "Print"
    }).then(function (ok) {
      if (!ok) return;
      buildRecoverySheet(critical);
      document.body.classList.add("printing-sheet");
      // Let the DOM paint the sheet before the (blocking) print dialog opens.
      setTimeout(function () {
        window.print();
      }, 50);
      settingsMsg("recovery-msg", "Sent " + critical.length + " entries to your printer.", false);
    });
  }

  // Tidy up after the print dialog closes (or is cancelled).
  window.addEventListener("afterprint", clearRecoverySheet);

  /* ==================== settings-screen controls ==================== */
  // These live in the swapped-in Settings fragment, so bind via delegation.

  function settingsMsg(id, text, isError) {
    var m = byId(id);
    if (!m) return;
    m.textContent = text;
    m.classList.toggle("form-msg-error", !!isError);
    show(m, true);
  }

  document.body.addEventListener("click", function (e) {
    if (e.target.closest("#lock-btn")) {
      lockNow();
      return;
    }
    if (e.target.closest("#sync-now")) {
      if (window.Sync) Sync.syncNow();
      return;
    }
    if (e.target.closest("#vault-id-copy")) {
      if (window.Sync) copyValue(Sync.getVaultId(), false);
      return;
    }
    if (e.target.closest("#recovery-print")) {
      printRecoverySheet();
      return;
    }
    if (e.target.closest("#vault-name-save")) {
      persistVaultName(byId("vault-name").value.trim());
      settingsMsg(
        "vault-name-msg",
        "Saved and synced to your other devices. An already-installed app keeps " +
          "its old icon name until you reinstall it.",
        false
      );
      return;
    }
    if (e.target.closest("#export-btn")) {
      Vault.exportVault(window.Sync ? Sync.getVaultId() : "").then(function (blob) {
        var url = URL.createObjectURL(blob);
        var stamp = new Date().toISOString().slice(0, 10);
        var a = el("a", { href: url, download: "ownvault-backup-" + stamp + ".json" });
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () {
          URL.revokeObjectURL(url);
        }, 1000);
        settingsMsg("backup-msg", "Backup downloaded.", false);
      }, function () {
        settingsMsg("backup-msg", "Nothing to export yet.", true);
      });
    }
  });

  document.body.addEventListener("change", function (e) {
    if (e.target.id === "clip-clear-select") {
      try {
        localStorage.setItem(CLIP_CLEAR_KEY, e.target.value);
      } catch (err) {
        /* setting applies for this session but won't persist */
      }
      return;
    }
    if (e.target.id === "sync-enable") {
      if (window.Sync) Sync.setEnabled(e.target.checked);
      return;
    }
    if (e.target.id === "sync-token") {
      if (window.Sync) {
        Sync.setToken(e.target.value.trim());
        Sync.syncNow();
      }
      return;
    }
    if (e.target.id === "csv-file") {
      handleCsvFile(e);
      return;
    }
    if (e.target.id !== "import-file") return;
    var input = e.target;
    var file = input.files && input.files[0];
    input.value = ""; // reset now so re-selecting the same file re-fires change
    if (!file) return;
    var warn =
      "It replaces this device's vault with the backup's contents.";
    if (!window.Sync || Sync.isEnabled()) {
      warn +=
        " Because sync is on, the backup's entries also overwrite the matching " +
        "ones on the server and your other devices (entries that exist only on " +
        "the server are kept).";
    }
    warn += "\n\nThis can't be undone.";
    confirmDialog({
      title: "Restore this backup?",
      message: warn,
      confirmText: "Restore"
    }).then(function (ok) {
      if (!ok) return;
      var reader = new FileReader();
      reader.onload = function () {
        Vault.importVault(String(reader.result)).then(
          function (res) {
            // Reattach to the vault the backup came from (v2 backups), so the
            // restored device rejoins the same server namespace and keeps syncing
            // with any surviving devices instead of forking a new vault.
            if (res.vaultId && window.Sync) Sync.setVaultId(res.vaultId);
            settingsMsg("backup-msg", "Imported " + res.entries + " entries. Unlock with that backup's password.", false);
            lockNow();
          },
          function (err) {
            settingsMsg("backup-msg", (err && err.message) || "Import failed.", true);
          }
        );
      };
      reader.readAsText(file);
    });
  });

  // CSV import (Settings): parse first — no writes — so the confirm dialog can
  // say exactly how many entries the file holds before anything is committed.
  // Vault.parseCSV throws on files that don't look like a password export.
  function handleCsvFile(e) {
    var input = e.target;
    var file = input.files && input.files[0];
    input.value = ""; // reset so re-selecting the same file re-fires change
    if (!file) return;
    if (!Vault.isUnlocked()) {
      settingsMsg("csv-msg", "Unlock the vault first.", true);
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      var parsed;
      try {
        parsed = Vault.parseCSV(String(reader.result));
      } catch (err) {
        settingsMsg("csv-msg", (err && err.message) || "Couldn't read that CSV.", true);
        return;
      }
      var n = parsed.entries.length;
      var msg =
        n + (n > 1 ? " entries" : " entry") + " found in " + file.name +
        (parsed.skipped ? " (" + parsed.skipped + " empty rows skipped)" : "") +
        ". They'll be added to your vault — nothing existing is changed." +
        "\n\nThe CSV file itself is unencrypted: delete it, and empty the bin, " +
        "once the import is done.";
      confirmDialog({
        title: "Import " + n + (n > 1 ? " entries?" : " entry?"),
        message: msg,
        confirmText: "Import"
      }).then(function (ok) {
        if (!ok) return;
        Vault.putMany(parsed.entries).then(
          function (added) {
            settingsMsg("csv-msg", "Imported " + added + (added > 1 ? " entries." : " entry."), false);
          },
          function () {
            settingsMsg("csv-msg", "Import failed — nothing was added.", true);
          }
        );
      });
    };
    reader.readAsText(file);
  }

  document.body.addEventListener("submit", function (e) {
    if (e.target.id !== "change-pw-form") return;
    e.preventDefault();
    var f = e.target;
    if (f["new"].value.length < 12) {
      settingsMsg(
        "change-pw-msg",
        "New password must be at least 12 characters — a few random words make a strong passphrase.",
        true
      );
      return;
    }
    if (f["new"].value !== f.new2.value) {
      settingsMsg("change-pw-msg", "New passwords don't match.", true);
      return;
    }
    Vault.changePassword(f.old.value, f["new"].value).then(function (ok) {
      if (ok) {
        f.reset();
        settingsMsg("change-pw-msg", "Master password changed.", false);
      } else {
        settingsMsg("change-pw-msg", "Current password is incorrect.", true);
      }
    });
  });

  /* ==================== conflicts + sync status ==================== */

  function showConflictBanner(n) {
    var b = byId("conflict-banner");
    if (!b) return;
    if (n > 0) {
      byId("conflict-banner-text").textContent =
        n + " sync conflict" + (n > 1 ? "s" : "") + " — tap to resolve";
      b.hidden = false;
    } else {
      b.hidden = true;
    }
  }

  function refreshConflicts() {
    if (!Vault.isUnlocked()) {
      showConflictBanner(0);
      return;
    }
    Vault.conflictCount().then(showConflictBanner);
  }

  function versionBlock(labelText, v) {
    var rows = [el("div", { class: "field-label", text: labelText })];
    if (!v) {
      rows.push(el("div", { class: "cfx-note", text: "(unavailable)" }));
    } else if (v.deleted) {
      rows.push(el("div", { class: "cfx-note", text: "Deleted" }));
    } else {
      [
        ["Title", v.title],
        ["Username", v.username],
        ["Password", v.password],
        ["URL", v.url],
        ["Notes", v.notes]
      ].forEach(function (p) {
        if (p[1]) rows.push(el("div", { class: "cfx-line", text: p[0] + ": " + p[1] }));
      });
    }
    return el("div", { class: "cfx-side" }, rows);
  }

  function renderConflict(c) {
    var title =
      (c.mine && c.mine.title) || (c.theirs && c.theirs.title) || "(entry)";
    return el("div", { class: "cfx", "data-cfx-id": c.id }, [
      el("div", { class: "cfx-title", text: title }),
      el("div", { class: "cfx-cols" }, [
        versionBlock("This device", c.mine),
        versionBlock("Server", c.theirs)
      ]),
      el("div", { class: "cfx-actions" }, [
        el("button", { class: "btn", type: "button", "data-keep": "mine", text: "Keep this device" }),
        el("button", { class: "btn btn-ghost", type: "button", "data-keep": "theirs", text: "Keep server" })
      ])
    ]);
  }

  function openConflictModal() {
    if (!Vault.isUnlocked()) return;
    Vault.listConflicts().then(function (conflicts) {
      var card = byId("conflict-card");
      card.innerHTML = "";
      card.appendChild(
        el("div", { class: "modal-head" }, [
          el("h2", { class: "modal-title", text: "Resolve conflicts" }),
          el("button", {
            class: "icon-btn modal-close",
            type: "button",
            "data-cclose": "1",
            "aria-label": "Close",
            text: "✕"
          })
        ])
      );
      if (!conflicts.length) {
        card.appendChild(el("p", { class: "card-note", text: "No conflicts remaining." }));
      } else {
        var body = el("div", { class: "modal-body" }, conflicts.map(renderConflict));
        card.appendChild(body);
      }
      show(byId("conflict-modal"), true);
      document.body.classList.add("modal-open");
    });
  }

  function closeConflictModal() {
    var m = byId("conflict-modal");
    if (m && !m.hidden) {
      m.hidden = true;
      byId("conflict-card").innerHTML = "";
    }
    if (byId("record-modal").hidden) document.body.classList.remove("modal-open");
  }

  byId("conflict-banner").addEventListener("click", openConflictModal);

  byId("conflict-modal").addEventListener("click", function (e) {
    if (e.target.closest("[data-cclose]")) {
      closeConflictModal();
      return;
    }
    var keepBtn = e.target.closest("[data-keep]");
    if (keepBtn) {
      var wrap = keepBtn.closest("[data-cfx-id]");
      var id = wrap.getAttribute("data-cfx-id");
      var keep = keepBtn.getAttribute("data-keep");
      Vault.resolveConflict(id, keep).then(function () {
        if (window.Sync) Sync.syncSoon(); // push the resolution
        openConflictModal(); // re-render remaining
      });
    }
  });

  byId("confirm-ok").addEventListener("click", function () {
    closeConfirm(true);
  });
  byId("confirm-cancel").addEventListener("click", function () {
    closeConfirm(false);
  });
  byId("confirm-modal").addEventListener("click", function (e) {
    if (e.target.closest("[data-xclose]")) closeConfirm(false);
  });

  // Live sync status -> conflict banner + Settings status line.
  if (window.Sync) {
    Sync.onStatus(function (s) {
      showConflictBanner(s.conflicts || 0);
      var el2 = byId("sync-status");
      if (el2) el2.textContent = s.message || "";
    });
  }

  /* ==================== change + escape wiring ==================== */

  // Re-render the list when entries change under us (add/edit/delete/sync),
  // and schedule a push of local changes.
  Vault.onChange(function (local) {
    if (Vault.isUnlocked()) {
      loadEntries();
      refreshConflicts();
      reconcileVaultName(); // a rename synced from another device lands here
    }
    // Only a genuine local edit needs pushing. Scheduling a sync on sync-applied
    // changes too would loop forever (every sync refreshes -> schedules a sync).
    if (local && window.Sync) Sync.syncSoon();
  });

  // Close modals on Escape. The confirm dialog is topmost, so it goes first
  // (Escape = cancel).
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (!byId("confirm-modal").hidden) closeConfirm(false);
    else if (!byId("conflict-modal").hidden) closeConflictModal();
    else if (!byId("record-modal").hidden) closeModal();
  });

  startGate();
})();
