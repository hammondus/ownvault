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
    clearInvalid();
  }

  /* ---------- field-level errors ---------- */
  // Point an error at the field it is about. The connect form has three
  // inputs and one button, so "no vault found there" alone leaves the user
  // to work out which one to change. markInvalid rings the named fields and
  // focuses the first, because the fix is always "type here". aria-invalid
  // carries the same fact to a screen reader, which can't see the ring.
  // Mirrors markInvalid/clearLockInvalid in the PWA's vaultui.js.
  function markInvalid(ids) {
    ids.forEach(function (id, n) {
      var f = byId(id);
      if (!f) return;
      f.classList.add("invalid");
      f.setAttribute("aria-invalid", "true");
      if (n === 0) f.focus();
    });
  }

  function clearInvalid() {
    var fields = document.querySelectorAll("input.invalid");
    for (var i = 0; i < fields.length; i++) {
      fields[i].classList.remove("invalid");
      fields[i].removeAttribute("aria-invalid");
    }
  }

  // Typing in a ringed field is the fix, so drop the ring on the first
  // keystroke rather than making the user submit again to clear it.
  document.addEventListener("input", function (e) {
    if (!e.target || !e.target.classList) return;
    e.target.classList.remove("invalid");
    e.target.removeAttribute("aria-invalid");
  });

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

  // Injected into every frame of the active tab, and only on a Fill click.
  // executeScript serializes this function and rebuilds it in the page, so it
  // closes over nothing here — every helper it needs is nested inside.
  //
  // The password field anchors the search: take the first visible one, then
  // the last visible text-ish input before it in the same form (or the whole
  // document on formless pages). A username-first two-step login has no
  // password field on screen and gets the username only, which is still a
  // fill. Returns the list of fields filled, so the caller can tell which
  // frame held the form.
  function fillFields(username, password) {
    function visible(el) {
      if (!el) return false;
      var r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }

    // React and friends track the native value setter rather than the
    // attribute, so a bare assignment leaves the framework's own state stale
    // and the form submits empty.
    function setValue(input, value) {
      var proto = Object.getPrototypeOf(input);
      var desc =
        Object.getOwnPropertyDescriptor(proto, "value") ||
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
      if (desc && desc.set) desc.set.call(input, value);
      else input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }

    var pws = Array.prototype.filter.call(
      document.querySelectorAll('input[type="password"]'),
      visible
    );
    var pw = pws[0] || null;
    var scope = (pw && pw.form) || document;
    var candidates = Array.prototype.filter.call(
      scope.querySelectorAll(
        'input[type="text"], input[type="email"], input:not([type])'
      ),
      visible
    );
    var user = null;
    if (pw) {
      var pos = pw.compareDocumentPosition.bind(pw);
      for (var i = 0; i < candidates.length; i++) {
        if (pos(candidates[i]) & Node.DOCUMENT_POSITION_PRECEDING) user = candidates[i];
      }
    } else {
      user = candidates[0] || null;
    }

    var filled = [];
    if (user && username) {
      setValue(user, username);
      filled.push("username");
    }
    if (pw && password) {
      setValue(pw, password);
      filled.push("password");
    }
    return filled;
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
        // allFrames because login forms are routinely in an iframe, leaving
        // the top frame with no inputs at all; a hosted SSO widget always is.
        // executeScript returns one entry per frame, which is what makes this
        // reliable: a runtime message to the tab would resolve with whichever
        // frame answered first, usually the empty top one.
        chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          func: fillFields,
          args: [e.username || "", e.password || ""]
        }).then(function (results) {
          // Only one frame holds the form, and frames that can't be injected
          // report no result at all. Take the best answer: a frame that filled
          // both fields beats one that only found a username.
          var got = [];
          (results || []).forEach(function (r) {
            if (r && r.result && r.result.length > got.length) got = r.result;
          });
          if (got.length) {
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

  // Loopback matches main.go's isLoopbackHost. With TLS up the server serves
  // plain HTTP to loopback and redirects everything else, so http:// for a
  // local dev server and https:// for anything that leaves the machine is
  // what the server itself will accept. Never guess the other way round: the
  // access token would ride an unencrypted hop.
  function isLoopback(host) {
    return (
      host === "localhost" ||
      host === "[::1]" ||
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
    );
  }

  // Typing "vault.example.com" is the obvious thing to do, and Sync.setServerUrl
  // only trims — a schemeless value becomes a relative fetch against the
  // extension's own origin. Fill the scheme in and write it back to the field,
  // so the value on screen is the value that gets stored. A scheme needs the
  // "//": "localhost:8080" parses as the protocol "localhost:", and is a host
  // and port typed without one.
  function normalizeServerUrl() {
    var f = byId("c-server");
    var addr = f.value.trim();
    if (!addr || /^[a-z][a-z0-9+.-]*:\/\//i.test(addr)) {
      f.value = addr;
      return;
    }
    var host = "";
    try {
      host = new URL("https://" + addr).hostname;
    } catch (e) {
      /* malformed either way — left to connectFieldError */
    }
    f.value = (isLoopback(host) ? "http://" : "https://") + addr;
  }

  // The form carries novalidate: these checks say the same thing the native
  // `required` bubble would, but in the popup's own error line and with the
  // offending field ringed. They run after normalizeServerUrl, so a bare host
  // already carries a scheme and what reaches here is genuinely malformed.
  // The protocol check keeps anything but http(s) out of a value that goes
  // straight to fetch().
  function connectFieldError() {
    var url = byId("c-server").value.trim();
    if (!url) return { msg: "Enter your Own Vault server's address.", fields: ["c-server"] };
    var parsed = null;
    try {
      parsed = new URL(url);
    } catch (e) {
      /* reported below */
    }
    if (!parsed || (parsed.protocol !== "https:" && parsed.protocol !== "http:")) {
      return {
        msg: "That server address isn't valid. Use your server's web address, like vault.example.com.",
        fields: ["c-server"]
      };
    }
    if (!byId("c-vault").value.trim()) {
      return {
        msg: "Enter the Vault ID. Find it in the app under Settings.",
        fields: ["c-vault"]
      };
    }
    return null;
  }

  byId("connect-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var errEl = byId("connect-err");
    errEl.hidden = true;
    clearInvalid();
    normalizeServerUrl();

    var bad = connectFieldError();
    if (bad) {
      errEl.textContent = bad.msg;
      errEl.hidden = false;
      markInvalid(bad.fields);
      return;
    }

    call("ov:connect", {
      serverUrl: byId("c-server").value,
      vaultId: byId("c-vault").value,
      token: byId("c-token").value
    }).then(function (res) {
      if (res.exists) return show("unlock-view");
      if (res.needsAuth) {
        errEl.textContent = "Access token required or incorrect.";
        errEl.hidden = false;
        markInvalid(["c-token"]);
        return;
      }
      // Both stay ambiguous here: bootstrap resolves the same way whether the
      // server answered "no such vault" or was never reached at all. Ring the
      // two fields the message names, and focus the Vault ID — the one that
      // gets typed by hand off another device.
      errEl.textContent = "No vault found there — check the server URL and Vault ID.";
      errEl.hidden = false;
      markInvalid(["c-vault", "c-server"]);
    }, function (err) {
      // A transport/host failure, not a field the user can correct.
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
