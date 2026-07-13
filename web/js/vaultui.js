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

  /* ==================== tiny DOM helper ==================== */

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = attrs[k];
        else if (k === "html") node.innerHTML = attrs[k];
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

  /* ==================== lock gate ==================== */

  function showLock(mode) {
    document.body.classList.add("locked");
    show(byId("lock-screen"), true);
    show(byId("create-form"), mode === "create");
    show(byId("unlock-form"), mode === "unlock");
    show(byId("create-error"), false);
    show(byId("unlock-error"), false);
    var focus = byId(mode === "create" ? "create-pw" : "unlock-pw");
    if (focus) {
      focus.value = "";
      var other = byId("create-pw2");
      if (other) other.value = "";
      var up = byId("unlock-pw");
      if (up) up.value = "";
      setTimeout(function () {
        focus.focus();
      }, 50);
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
      // Fresh device: try to pull an existing vault (meta + entries) from the
      // server so we can offer "unlock" instead of "create".
      if (window.Sync && Sync.isEnabled()) {
        Sync.bootstrap().then(function (nowExists) {
          showLock(nowExists ? "unlock" : "create");
        });
      } else {
        showLock("create");
      }
    });
  }

  function afterUnlock() {
    hideLock();
    resetIdle();
    loadEntries();
    if (window.Sync) Sync.start();
    refreshConflicts();
  }

  function handleCreate(e) {
    e.preventDefault();
    var pw = byId("create-pw").value;
    var pw2 = byId("create-pw2").value;
    var err = byId("create-error");
    if (pw.length < 8) {
      err.textContent = "Use at least 8 characters.";
      show(err, true);
      return;
    }
    if (pw !== pw2) {
      err.textContent = "The two passwords don't match.";
      show(err, true);
      return;
    }
    Vault.create(pw).then(afterUnlock, function () {
      err.textContent = "Couldn't create the vault.";
      show(err, true);
    });
  }

  function handleUnlock(e) {
    e.preventDefault();
    var pw = byId("unlock-pw").value;
    var err = byId("unlock-error");
    Vault.unlock(pw).then(function (ok) {
      if (ok) {
        afterUnlock();
      } else {
        err.textContent = "Incorrect master password.";
        show(err, true);
        byId("unlock-pw").select();
      }
    });
  }

  function lockNow() {
    Vault.lock();
    if (window.Sync) Sync.stop();
    entries = [];
    searchTerm = "";
    closeModal();
    closeConflictModal();
    var list = byId("pw-list");
    if (list) list.innerHTML = "";
    showConflictBanner(0);
    clearTimeout(idleTimer);
    showLock("unlock");
  }

  /* ==================== auto-lock ==================== */

  function resetIdle() {
    if (!Vault.isUnlocked()) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(lockNow, AUTO_LOCK_MS);
  }

  ["pointerdown", "keydown"].forEach(function (evt) {
    document.addEventListener(evt, function () {
      if (Vault.isUnlocked()) resetIdle();
    });
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

    card.appendChild(
      el("div", { class: "modal-head" }, [
        el("h2", { class: "modal-title", text: entry.title || "(untitled)" }),
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

  function inputField(name, labelText, value, type) {
    var input = el("input", {
      class: "form-input",
      type: type || "text",
      name: name,
      autocomplete: "off",
      value: value || ""
    });
    return el("label", { class: "form-row" }, [
      el("span", { class: "form-label", text: labelText }),
      input
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
      rows: "3"
    });
    notes.value = entry.notes || "";

    // novalidate: the url field pre-fills a bare "https://" that native
    // type=url validation would reject and silently block submission on; we
    // normalise the url ourselves in saveFromForm.
    var form = el("form", { id: "record-form", class: "modal-body", novalidate: "novalidate" }, [
      inputField("title", "Title", entry.title, "text"),
      inputField("username", "Username", entry.username, "text"),
      inputField("password", "Password", entry.password, "text"),
      // Pre-fill the scheme on new entries to save typing; a bare scheme is
      // treated as empty on save.
      inputField("url", "URL", entry.id ? entry.url : entry.url || "https://", "url"),
      el("label", { class: "form-row" }, [
        el("span", { class: "form-label", text: "Notes" }),
        notes
      ])
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
      notes: form.notes.value
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
    if (!window.confirm("Delete this entry? This can't be undone.")) return;
    Vault.remove(id).then(closeModal);
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
    document.body.classList.remove("modal-open");
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
    }
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
    if (e.target.closest("#export-btn")) {
      Vault.exportVault().then(function (blob) {
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
    if (e.target.id !== "import-file") return;
    var file = e.target.files && e.target.files[0];
    if (!file) return;
    if (
      !window.confirm(
        "Importing replaces the current vault with the backup's contents. Continue?"
      )
    ) {
      e.target.value = "";
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      Vault.importVault(String(reader.result)).then(
        function (n) {
          settingsMsg("backup-msg", "Imported " + n + " entries. Unlock with that backup's password.", false);
          lockNow();
        },
        function (err) {
          settingsMsg("backup-msg", (err && err.message) || "Import failed.", true);
        }
      );
    };
    reader.readAsText(file);
    e.target.value = "";
  });

  document.body.addEventListener("submit", function (e) {
    if (e.target.id !== "change-pw-form") return;
    e.preventDefault();
    var f = e.target;
    if (f["new"].value.length < 8) {
      settingsMsg("change-pw-msg", "New password must be at least 8 characters.", true);
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
  Vault.onChange(function () {
    if (Vault.isUnlocked()) {
      loadEntries();
      refreshConflicts();
    }
    if (window.Sync) Sync.syncSoon();
  });

  // Close modals on Escape.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (!byId("conflict-modal").hidden) closeConflictModal();
    else if (!byId("record-modal").hidden) closeModal();
  });

  startGate();
})();
