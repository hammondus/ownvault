/*
 * Own Vault extension — popup UI.
 *
 * Thin client over the offscreen vault host: every secret is fetched
 * per-entry on demand and lives only as long as the view showing it. The
 * popup's own lifetime is one open-close; state worth keeping (unlock,
 * config, sync) all lives in offscreen.js.
 */
"use strict";

(function () {
  function byId(id) {
    return document.getElementById(id);
  }

  // All ov:* calls go through here. The first message of a session may find
  // no offscreen document yet (fresh browser start), so ask the service
  // worker to ensure it, once, then retry.
  var ensured = false;
  function call(type, payload) {
    var msg = Object.assign({ type: type }, payload || {});
    function send() {
      return chrome.runtime.sendMessage(msg).then(function (res) {
        if (!res) throw new Error("no response from vault host");
        if (!res.ok) throw new Error(res.error || "vault error");
        return res.data;
      });
    }
    if (ensured) return send();
    return chrome.runtime.sendMessage({ type: "ov:ensure" }).then(function () {
      ensured = true;
      return send();
    });
  }

  /* ---------- view switching ---------- */

  var views = ["connect-view", "unlock-view", "list-view", "detail-view"];
  function show(view) {
    views.forEach(function (v) {
      byId(v).hidden = v !== view;
    });
    byId("lock-btn").hidden = view === "connect-view" || view === "unlock-view";
  }

  function toast(msg) {
    var t = byId("toast");
    t.textContent = msg;
    t.hidden = false;
    setTimeout(function () {
      t.hidden = true;
    }, 1800);
  }

  /* ---------- active tab ---------- */

  var tab = null; // {id, host} of the page the popup was opened over

  function activeTab() {
    return chrome.tabs.query({ active: true, currentWindow: true }).then(function (tabs) {
      var t = tabs[0];
      if (!t || !/^https?:/i.test(t.url || "")) return null;
      var m = /^https?:\/\/([^\/:?#]+)/i.exec(t.url);
      return { id: t.id, host: m ? m[1].toLowerCase() : "" };
    });
  }

  /* ---------- list ---------- */

  var entries = [];

  function entryLi(e) {
    var li = document.createElement("li");
    li.dataset.id = e.id;
    var t = document.createElement("div");
    t.className = "pw-item-title";
    t.textContent = e.title || "(untitled)";
    li.appendChild(t);
    var sub = [e.username, e.url].filter(Boolean).join("  •  ");
    if (sub) {
      var s = document.createElement("div");
      s.className = "pw-item-sub";
      s.textContent = sub;
      li.appendChild(s);
    }
    return li;
  }

  function renderList() {
    var term = byId("search").value.trim().toLowerCase();
    var ul = byId("pw-list");
    ul.innerHTML = "";
    var shown = entries.filter(function (e) {
      if (!term) return true;
      return (e.title + "\n" + e.username + "\n" + e.url).toLowerCase().indexOf(term) !== -1;
    });
    shown.forEach(function (e) {
      ul.appendChild(entryLi(e));
    });
    var empty = byId("empty");
    empty.hidden = !!shown.length;
    empty.textContent = entries.length ? "No matches." : "Vault is empty.";
  }

  function loadList() {
    return call("ov:list")
      .then(function (rows) {
        entries = rows;
        renderList();
        if (!tab || !tab.host) {
          byId("site-block").hidden = true;
          return;
        }
        return call("ov:matches", { host: tab.host }).then(function (m) {
          byId("site-block").hidden = !m.length;
          var ul = byId("site-list");
          ul.innerHTML = "";
          m.forEach(function (e) {
            ul.appendChild(entryLi(e));
          });
        });
      })
      .then(function () {
        show("list-view");
        byId("search").focus();
      });
  }

  /* ---------- detail ---------- */

  var totpTimer = null;
  var currentTotpCode = "";

  function stopTotp() {
    clearInterval(totpTimer);
    totpTimer = null;
    currentTotpCode = "";
  }

  function field(label, value, opts) {
    opts = opts || {};
    var wrap = document.createElement("div");
    wrap.className = "field";
    var l = document.createElement("div");
    l.className = "field-label";
    l.textContent = label;
    wrap.appendChild(l);
    var body = document.createElement("div");
    body.className = "field-body";
    var v = document.createElement("span");
    v.className = "field-value" + (opts.masked ? " masked" : "") + (opts.mono ? " totp-code" : "");
    v.textContent = value;
    body.appendChild(v);
    if (opts.time) {
      body.appendChild(opts.time);
    }
    if (opts.copy) {
      var b = document.createElement("button");
      b.className = "icon-btn";
      b.textContent = "⧉";
      b.setAttribute("aria-label", "Copy " + label);
      b.addEventListener("click", function () {
        copy(opts.copy(), opts.wipe);
      });
      body.appendChild(b);
    }
    wrap.appendChild(body);
    return wrap;
  }

  function copy(value, wipe) {
    navigator.clipboard.writeText(value).then(function () {
      if (wipe) {
        // The wipe timer must outlive this popup — offscreen.js owns it.
        call("ov:clip-wipe");
        toast("Copied — clears in 20s");
      } else {
        toast("Copied");
      }
    });
  }

  function openDetail(id) {
    call("ov:credentials", { id: id }).then(function (e) {
      stopTotp();
      byId("d-title").textContent = e.title || "(untitled)";
      var f = byId("d-fields");
      f.innerHTML = "";
      if (e.username)
        f.appendChild(field("Username", e.username, { copy: function () { return e.username; } }));
      if (e.password)
        f.appendChild(field("Password", e.password, {
          masked: true,
          wipe: true,
          copy: function () { return e.password; }
        }));
      if (e.totp) {
        currentTotpCode = e.totp.code;
        var time = document.createElement("span");
        time.className = "totp-time";
        var row = field("Verification code", e.totp.code.slice(0, 3) + " " + e.totp.code.slice(3), {
          mono: true,
          time: time,
          copy: function () { return currentTotpCode; }
        });
        var codeNode = row.querySelector(".field-value");
        var tick = function () {
          call("ov:totp", { id: id }).then(function (r) {
            currentTotpCode = r.code;
            codeNode.textContent = r.code.slice(0, 3) + " " + r.code.slice(3);
            time.textContent = r.secondsLeft + "s";
          }, stopTotp);
        };
        time.textContent = e.totp.secondsLeft + "s";
        totpTimer = setInterval(tick, 1000);
        f.appendChild(row);
      }
      if (e.url) f.appendChild(field("URL", e.url, { copy: function () { return e.url; } }));

      var fill = byId("fill-btn");
      fill.hidden = !tab || (!e.username && !e.password);
      fill.onclick = function () {
        chrome.tabs.sendMessage(tab.id, {
          type: "ov:fill",
          username: e.username,
          password: e.password
        }).then(function (res) {
          if (res && res.filled && res.filled.length) {
            if (e.totp) {
              // 2FA prompt comes next on most sites; hand the code over.
              copy(currentTotpCode, false);
              toast("Filled — code copied");
            } else {
              toast("Filled");
            }
            setTimeout(function () { window.close(); }, e.totp ? 900 : 400);
          } else {
            toast("No login fields found");
          }
        }).catch(function () {
          toast("Can't fill this page");
        });
      };
      show("detail-view");
    }, function (err) {
      toast(err.message);
    });
  }

  /* ---------- wiring ---------- */

  byId("connect-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var errEl = byId("connect-err");
    errEl.hidden = true;
    call("ov:connect", {
      serverUrl: byId("c-server").value,
      vaultId: byId("c-vault").value,
      token: byId("c-token").value
    }).then(function (res) {
      if (res.exists) return show("unlock-view");
      errEl.textContent = res.needsAuth
        ? "Server refused the token."
        : "No vault found there — check the server URL and Vault ID.";
      errEl.hidden = false;
    }, function (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    });
  });

  byId("unlock-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var errEl = byId("unlock-err");
    errEl.hidden = true;
    call("ov:unlock", { password: byId("u-pw").value }).then(function () {
      byId("u-pw").value = "";
      loadList();
    }, function (err) {
      errEl.textContent = err.message || "Incorrect master password.";
      errEl.hidden = false;
    });
  });

  byId("lock-btn").addEventListener("click", function () {
    stopTotp();
    call("ov:lock").then(function () {
      show("unlock-view");
    });
  });

  byId("search").addEventListener("input", renderList);

  byId("back-btn").addEventListener("click", function () {
    stopTotp();
    show("list-view");
  });

  document.addEventListener("click", function (ev) {
    var li = ev.target.closest(".pw-list li");
    if (li) openDetail(li.dataset.id);
  });

  // A pulled sync or a lock can move state under an open popup.
  chrome.runtime.onMessage.addListener(function (msg) {
    if (!msg || msg.type !== "ov:changed") return;
    if (msg.locked) {
      stopTotp();
      show("unlock-view");
    } else if (!byId("list-view").hidden) {
      loadList();
    }
  });

  /* ---------- start ---------- */

  activeTab()
    .then(function (t) {
      tab = t;
      return call("ov:status");
    })
    .then(function (st) {
      if (st.unlocked) return loadList();
      if (st.initialized) return show("unlock-view");
      // Configured but no local vault (first pull failed): back to connect,
      // with what's known prefilled so retrying is one click.
      byId("c-server").value = st.serverUrl || "";
      byId("c-vault").value = st.vaultId || "";
      show("connect-view");
    }, function (err) {
      show("connect-view");
      var e = byId("connect-err");
      e.textContent = err.message;
      e.hidden = false;
    });
})();
