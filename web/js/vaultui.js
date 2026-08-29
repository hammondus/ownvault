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
  var clipWipeDue = 0; // when a pending clipboard wipe comes due; 0 = none owed

  /* ==================== PWA install ==================== */
  // Chromium fires beforeinstallprompt when the app is installable; we stash the
  // event so the welcome step can offer an explicit "Install app" button (the
  // browser's own control is easy to miss). iOS Safari has no such API, so it
  // gets manual Add-to-Home-Screen steps instead. See updateInstallUI.
  var deferredInstallPrompt = null;

  // The shell owns display-mode detection (it also drives the manifest and the
  // page title from it). Guard for App in case this module is ever loaded
  // without the shell.
  function isStandalone() {
    return !!(window.App && App.isStandalone());
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

  // iOS WebKit doesn't repaint existing glyphs when -webkit-text-security
  // changes: a revealed field keeps showing dots while characters typed
  // *after* the toggle render correctly (desktop WebKit and Chromium repaint
  // fine). Rewriting the content forces a fresh text layout. For an input the
  // caret lands at the end, which is fine for a reveal tap. Call after every
  // masked-class toggle.
  function forceTextRepaint(node) {
    if (node.tagName === "INPUT" || node.tagName === "TEXTAREA") {
      var v = node.value;
      node.value = "";
      node.value = v;
    } else {
      var t = node.textContent;
      node.textContent = "";
      node.textContent = t;
    }
  }

  function show(node, on) {
    if (node) node.hidden = !on;
  }

  // Point an error message at the field it is about. Every lock-gate error is
  // a sentence about one input ("enter your Vault ID", "token required"), and
  // the connect form has two inputs whose roles are easy to mix up, so the
  // message alone leaves the user guessing. Focus follows the highlight: the
  // fix is always "type here". aria-invalid carries the same fact to a screen
  // reader, which can't see the ring.
  function markInvalid(id) {
    var f = byId(id);
    if (!f) return;
    f.classList.add("invalid");
    f.setAttribute("aria-invalid", "true");
    f.focus();
  }

  function clearInvalid(node) {
    if (!node || !node.classList) return;
    node.classList.remove("invalid");
    node.removeAttribute("aria-invalid");
  }

  // Reset every highlight under the lock screen. Called whenever a fresh
  // attempt starts, so a stale ring never outlives the message that set it.
  function clearLockInvalid() {
    var fields = document.querySelectorAll("#lock-screen .lock-input.invalid");
    for (var i = 0; i < fields.length; i++) clearInvalid(fields[i]);
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

  /* ==================== password strength meter ==================== */
  // Advisory only — the 12-character floor stays the single hard rule.
  // pwstrength.js scores; this renders into a .pw-meter block (bar + text).

  function renderStrength(container, pw) {
    if (!container || !window.PwStrength) return;
    if (!pw) {
      container.hidden = true;
      return;
    }
    var r = PwStrength.score(pw);
    container.hidden = false;
    container.className = "pw-meter s" + r.score;
    var text = container.querySelector(".pw-meter-text");
    if (text) {
      var label = r.label.charAt(0).toUpperCase() + r.label.slice(1);
      text.textContent =
        label + " — could be cracked offline " + r.crackTime + "." +
        (r.feedback ? " " + r.feedback : "");
    }
  }

  // The create field is persistent chrome; the change-password field lives in
  // the swapped-in Settings fragment, so it's delegated.
  byId("create-pw").addEventListener("input", function (e) {
    renderStrength(byId("create-strength"), e.target.value);
  });
  document.body.addEventListener("input", function (e) {
    if (e.target.name !== "new") return;
    if (e.target.closest("#change-pw-form")) {
      renderStrength(byId("change-strength"), e.target.value);
    } else if (e.target.closest("#reencrypt-form")) {
      renderStrength(byId("reenc-strength"), e.target.value);
    }
  });

  /* ==================== lock gate ==================== */

  // First 8 chars of a vault id: enough to tell vaults apart in the picker
  // when one has no name yet (ids are random UUIDs/hex).
  function shortId(id) {
    return (id || "").slice(0, 8) + "…";
  }

  function vaultLabel(id) {
    return (window.App && App.getVaultName(id)) || shortId(id);
  }

  function showLock(mode) {
    var vaults = window.Sync ? Sync.listVaults() : [];
    document.body.classList.add("locked");
    show(byId("lock-screen"), true);
    show(byId("create-form"), mode === "create");
    show(byId("unlock-form"), mode === "unlock");
    show(byId("connect-form"), mode === "connect");
    show(byId("welcome-panel"), mode === "welcome");
    show(byId("picker-panel"), mode === "picker");
    show(byId("create-error"), false);
    show(byId("unlock-error"), false);
    show(byId("connect-error"), false);
    show(byId("restore-msg"), false);
    clearLockInvalid();
    stopScan(); // reaching the gate mid-scan (connect or 2FA) must release the camera
    show(
      byId("connect-scan"),
      mode === "connect" &&
        !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)
    );
    // A device with several vaults says WHICH vault this password prompt is
    // for, and offers the picker; connect gets a way back to it.
    if (mode === "unlock") {
      var un = byId("unlock-vault-name");
      if (un) {
        // The name whenever there is one; the short id only when several
        // vaults make "which one?" a real question.
        var lbl = window.App ? App.getVaultName() : "";
        if (!lbl && vaults.length > 1 && window.Sync) lbl = shortId(Sync.getVaultId());
        un.textContent = lbl;
        show(un, !!lbl);
      }
      // Always offered: the picker is also the only road to "Add another
      // vault", so a single-vault device needs the link too.
      show(byId("unlock-switch"), vaults.length > 0);
    }
    show(byId("connect-back"), mode === "connect" && vaults.length > 0);
    if (mode === "picker") {
      var ul = byId("picker-list");
      if (ul) {
        ul.textContent = ""; // rebuild: names/registry may have changed
        vaults.forEach(function (vid) {
          var li = document.createElement("li");
          var b = document.createElement("button");
          b.type = "button";
          b.setAttribute("data-vault-id", vid);
          b.textContent = vaultLabel(vid);
          li.appendChild(b);
          ul.appendChild(li);
        });
      }
    }
    // The welcome step surfaces the freshly created vault's id (sync vaults
    // only) and offers to install the app.
    if (mode === "welcome") {
      var wid = byId("welcome-vault-id");
      if (wid) wid.value = window.Sync ? Sync.getVaultId() : "";
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
    show(byId("create-strength"), false); // fields were just cleared
    var focusId =
      mode === "create" ? "create-pw"
        : mode === "connect" ? "connect-id"
        : mode === "welcome" ? "welcome-continue"
        : "unlock-pw";
    var focus =
      mode === "picker"
        ? byId("picker-list").querySelector("button")
        : byId(focusId);
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

  /* ==================== QR scanner ==================== */
  // One shared in-page scanner with two callers: the connect screen (setup
  // codes) and the entry edit form (a site's otpauth:// 2FA QR). In-page,
  // because the OS camera app treats a scanned QR as a search (and on iOS a
  // QR link opens Safari — a different storage container than the installed
  // app). Safari has no BarcodeDetector, so decoding is the vendored jsQR
  // (loaded on first use — 127 KB nobody else pays for).

  var scanStream = null;
  var scanTimer = null;
  var jsqrPromise = null;

  function loadJsQR() {
    if (window.jsQR) return Promise.resolve();
    if (jsqrPromise) return jsqrPromise;
    jsqrPromise = new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = "/js/jsqr.min.js";
      s.onload = function () {
        resolve();
      };
      s.onerror = function () {
        jsqrPromise = null;
        reject(new Error("jsQR failed to load"));
      };
      document.head.appendChild(s);
    });
    return jsqrPromise;
  }

  function stopScan() {
    clearInterval(scanTimer);
    scanTimer = null;
    if (scanStream) {
      scanStream.getTracks().forEach(function (t) {
        t.stop();
      });
      scanStream = null;
    }
    var v = byId("scan-video");
    if (v) v.srcObject = null;
    show(byId("scan-overlay"), false);
  }

  // opts: { hint, onCode(text) -> truthy once handled (stops the scan;
  // falsy = not our QR, keep looking), onError(msg) }.
  function startScan(opts) {
    byId("scan-hint").textContent = opts.hint;
    loadJsQR()
      .then(function () {
        return navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment" }
        });
      })
      .then(function (stream) {
        scanStream = stream;
        var video = byId("scan-video");
        video.srcObject = stream;
        video.play();
        show(byId("scan-overlay"), true);
        // Decode ~5x/s from a downscaled frame — full-resolution frames make
        // jsQR chew CPU for no extra range.
        var canvas = document.createElement("canvas");
        var ctx = canvas.getContext("2d", { willReadFrequently: true });
        scanTimer = setInterval(function () {
          if (!video.videoWidth) return; // no frame yet
          var scale = Math.min(1, 480 / video.videoWidth);
          canvas.width = Math.round(video.videoWidth * scale);
          canvas.height = Math.round(video.videoHeight * scale);
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          var img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          var hit = window.jsQR(img.data, img.width, img.height);
          if (hit && opts.onCode(hit.data)) stopScan();
        }, 200);
      })
      .catch(function (e) {
        stopScan();
        opts.onError(
          e && e.name === "NotAllowedError"
            ? "Camera access was refused. Allow it in your browser settings."
            : "Couldn't start the camera."
        );
      });
  }

  function startConnectScan() {
    var err = byId("connect-error");
    show(err, false);
    startScan({
      hint:
        "Point the camera at the setup code QR on your other device " +
        "(Settings → Sync).",
      onCode: function (text) {
        if (!Sync.parseSetupCode(text)) return false;
        byId("connect-id").value = text.trim();
        // Straight into the connect attempt — the whole point of the scan
        // is not having to touch anything else.
        handleConnect({ preventDefault: function () {} });
        return true;
      },
      onError: function (msg) {
        err.textContent = msg + " Paste the setup code instead.";
        show(err, true);
      }
    });
  }

  // The edit form's "scan" button: read a site's 2FA enrolment QR straight
  // into the authenticator-key field. Non-otpauth QRs are ignored (keep
  // scanning — the camera may just not be aimed yet), but an otpauth URI the
  // vault can't store (HOTP, non-default parameters) ends the scan with the
  // normalize error: the user aimed at the right code, so silence would read
  // as a broken scanner.
  function startTotpScan() {
    startScan({
      hint: "Point the camera at the site's 2FA QR code.",
      onCode: function (text) {
        if (!/^otpauth:/i.test(text)) return false;
        var form = byId("record-form");
        if (!form) return true; // modal gone (auto-lock) — drop the secret
        try {
          form.totp.value = Totp.normalize(text);
        } catch (e) {
          toast(e.message);
        }
        return true;
      },
      onError: toast
    });
  }

  function startGate() {
    // A setup link's fragment always routes to connect, even on a device
    // that already has vaults — opening one IS the add-another-vault
    // gesture. (An id the device already holds is caught by handleConnect,
    // which just selects it.)
    var hash = window.location.hash;
    var hasCode =
      hash && hash.length > 1 && window.Sync && !!Sync.parseSetupCode(hash.slice(1));
    if (hasCode || !(window.Sync && Sync.listVaults().length)) {
      // No vaults on this device (or an incoming code): the user supplies an
      // existing Vault ID (connect), starts a new vault, or restores.
      showLock("connect");
      prefillFromHash(true);
      return;
    }
    // Straight to unlock of the active vault (selected at load from
    // currentVault or the icon's ?vault=); the picker is one tap away.
    showLock("unlock");
    prefillFromHash(false); // strip a fragment that didn't parse
  }

  // A setup link (the QR's URL form) lands here with the code in the fragment
  // — scanned by the OS camera app rather than the in-app scanner. Prefill
  // only when the connect form is the active gate (fill), and never
  // auto-connect: a page load shouldn't have side effects. The fragment is
  // stripped in every mode — it holds the token, which must not linger in
  // the address bar, and replaceState keeps it out of the history entry.
  function prefillFromHash(fill) {
    var hash = window.location.hash;
    if (!hash || hash.length < 2) return;
    var code = hash.slice(1);
    if (fill && window.Sync && Sync.parseSetupCode(code)) {
      byId("connect-id").value = code;
    }
    if (window.history && history.replaceState) {
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  // Connect this device to an existing vault: select its namespace, store the
  // token under it, then pull. Success (server had that vault's wrapped-key
  // record) registers the vault and routes to unlock; a bad token or unknown
  // id reports inline so the user can fix it. An id this device already holds
  // takes the same path on purpose — the pull is a cheap incremental for an
  // intact vault, and it restores the meta record if the browser evicted the
  // vault's IndexedDB (localStorage tends to outlive IndexedDB).
  function handleConnect(e) {
    e.preventDefault();
    var err = byId("connect-error");
    if (!window.Sync) {
      showLock("create");
      return;
    }
    clearLockInvalid();
    var id = byId("connect-id").value.trim();
    if (!id) {
      err.textContent = "Enter your setup code or Vault ID, or start a new vault.";
      show(err, true);
      markInvalid("connect-id");
      return;
    }
    // A pasted setup code carries the token too, so it wins over the
    // (probably empty) token field. Its origin part guards against pasting a
    // code minted by a different server into this one.
    var code = Sync.parseSetupCode(id);
    if (code) {
      if (code.url && window.location && code.url !== window.location.origin) {
        err.textContent =
          "That setup code is for " + code.url + " — open the app there to connect.";
        show(err, true);
        markInvalid("connect-id");
        return;
      }
      id = code.vaultId;
    }
    var known = Sync.listVaults().indexOf(id) >= 0;
    var prev = Sync.getVaultId();
    // Select BEFORE storing the token so it lands under this vault's key.
    // Registration waits for a successful pull — selecting alone must not
    // leave a ghost vault if the id turns out not to exist.
    Sync.selectVault(id);
    var typed = byId("connect-token").value.trim();
    if (code) {
      Sync.setToken(code.token);
    } else if (!known || typed) {
      // For a vault already on this device an empty field means "keep the
      // stored token", not "erase it".
      Sync.setToken(typed);
    }
    Sync.bootstrap().then(function (res) {
      if (res.exists) {
        // The vault name is inherited from the vault itself on first unlock
        // (reconcileVaultName), so there's nothing to ask for here.
        Sync.addVault(id);
        if (window.App) App.refreshVaultUI();
        showLock("unlock");
      } else if (res.needsAuth) {
        // Stay on this vault so fixing the token and resubmitting just works.
        err.textContent = "Access token required or incorrect.";
        show(err, true);
        markInvalid("connect-token");
      } else {
        // Unknown id on this server. For a NEW id, undo the probe's traces
        // (the empty DB the pull created, the config stored above) and fall
        // back to the previously active vault; a vault already registered on
        // this device is left alone — it exists here even if the server has
        // lost it.
        if (!known) {
          Vault.wipeLocal();
          Sync.removeVault(id);
          if (prev) Sync.selectVault(prev);
        }
        err.textContent =
          "No vault with that ID on this server. Check the ID, or start a new vault.";
        show(err, true);
        markInvalid("connect-id");
      }
    });
  }

  // "Start a new vault instead": keep any token the user typed (a shared server
  // may require it even to create), mint a fresh namespace, and collect a master
  // password. The token field is optional, so a required-but-missing (or wrong)
  // token must be caught here with an auth probe — otherwise the new vault
  // looks fine locally while every push quietly 401s, and the first sign of
  // trouble is a second device failing to connect. An unreachable server also
  // blocks: a *synced* vault only makes sense with a server that answers, and
  // legitimately-offline creation has its own button below (the only way to
  // even see this screen offline is a cached shell — a fresh device loaded the
  // page from the server moments ago).
  function handleConnectCreate() {
    if (!window.Sync) {
      showLock("create");
      return;
    }
    var err = byId("connect-error");
    show(err, false);
    clearLockInvalid();
    // Probe the TYPED token (even empty — that's what the new vault will
    // store) before minting anything, so a refused or unreachable server
    // leaves no half-configured vault behind.
    var typed = byId("connect-token").value.trim();
    Sync.checkAuth(typed).then(function (res) {
      if (res.offline) {
        err.textContent =
          "Can't reach the sync server. Check your connection, then try again.";
        show(err, true);
        return;
      }
      if (res.needsAuth) {
        err.textContent =
          "This server requires an access token (missing or incorrect). Enter it above, then start the new vault.";
        show(err, true);
        markInvalid("connect-token");
        return;
      }
      // Select but do NOT register yet: an abandoned create must not leave a
      // ghost vault in the picker. handleCreate registers on success.
      Sync.selectVault(Sync.newVaultId());
      Sync.setToken(typed);
      showLock("create");
    });
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
          // importVault already switched to the backup's own vault; register
          // it so the picker and the next launch know it.
          hadEntries = false; // the lock-loop guard describes the old vault
          if (window.Sync) Sync.setVaultId(res.vaultId);
          if (window.App) App.refreshVaultUI();
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
      // The vault now exists: register it so the picker and the next launch
      // know it (the connect screen deliberately selects without registering).
      if (window.Sync) Sync.addVault(Sync.getVaultId());
      // Adopt the vault name: labels the installed app icon + lock screen (App)
      // and stores it as an encrypted, synced setting (Vault) so other devices
      // inherit it. Applied before the welcome step so the install button there
      // already advertises the chosen name in the manifest.
      if (name) persistVaultName(name);
      else if (window.App) App.refreshVaultUI(); // manifest gets the new id
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
      function (failure) {
        // Never leave the button dead: surface the failure instead of the old
        // silent unhandled-rejection (which is what iOS-over-HTTP hit).
        // Fatal derivation errors (e.g. the Argon2 module didn't load) carry
        // a user-facing message — show it rather than a generic shrug.
        err.textContent =
          failure && failure.fatal && failure.message
            ? failure.message
            : webCryptoReady()
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
    hideSetupQR(); // the QR shows the token; don't leave it behind the gate
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

  var hadEntries = false; // decrypted at least one row this session

  function loadEntries() {
    if (!Vault.isUnlocked()) return;
    Vault.list().then(function (rows) {
      // Rows all failing to decrypt while envelopes exist — after they
      // decrypted fine earlier this session — means the vault key changed
      // under us (a full re-encrypt on another device). Lock so the user
      // re-unlocks with the new master password, instead of silently showing
      // an empty vault. The hadEntries guard stops a fresh session that never
      // decrypted anything (e.g. foreign data) from lock-looping.
      if (!rows.length && hadEntries) {
        return Vault.liveEnvelopeCount().then(function (n) {
          if (n > 0 && Vault.isUnlocked()) {
            hadEntries = false;
            lockNow();
            var err = byId("unlock-error");
            if (err) {
              err.textContent =
                "The vault was re-encrypted (likely on another device). Unlock with the new master password.";
              show(err, true);
            }
            return;
          }
          entries = [];
          renderList();
        });
      }
      if (rows.length) hadEntries = true;
      entries = rows.sort(function (a, b) {
        return (a.title || "").localeCompare(b.title || "");
      });
      renderList();
    });
  }

  function matches(entry, term) {
    if (!term) return true;
    // Per spec: search spans every field, including password and notes, even
    // though only title/username/url are displayed. The authenticator key and
    // recovery codes stay out: matching against base32/code noise only
    // produces baffling results.
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

  /* ---------- live TOTP code (view modal) ---------- */
  // One timer, module-scoped so lock / close / mode-switch can always kill
  // it: the tick closure holds the secret, and it must not outlive the
  // modal's plaintext the way a stray interval would.

  var totpTimer = null;
  var totpCode = ""; // what the ⧉ button copies; cleared with the timer

  function stopTotp() {
    clearInterval(totpTimer);
    totpTimer = null;
    totpCode = "";
  }

  function totpRow(secret) {
    var codeNode = el("span", { class: "field-value totp-code", text: "· · ·" });
    var fill = el("span", { class: "totp-bar-fill" });
    var bar = el("span", { class: "totp-bar" }, [fill]);
    var timeNode = el("span", { class: "totp-time" });
    var copyBtn = el("button", {
      class: "icon-btn",
      type: "button",
      "data-copy-totp": "1",
      "aria-label": "Copy verification code",
      text: "⧉"
    });

    // Everything derives from Date.now() each tick (never a free-running
    // 30s timer): background tabs suspend timers, and on resume the next
    // tick lands on the right step immediately instead of drifting.
    var lastStep = -1;
    function tick() {
      var now = Date.now();
      var secondsLeft = Totp.PERIOD - (Math.floor(now / 1000) % Totp.PERIOD);
      timeNode.textContent = secondsLeft + "s";
      fill.style.width = (secondsLeft / Totp.PERIOD) * 100 + "%";
      var step = Math.floor(now / 1000 / Totp.PERIOD);
      if (step === lastStep) return;
      lastStep = step;
      Totp.code(secret, now).then(
        function (r) {
          totpCode = r.code;
          // Split 3+3: transcribing to another screen is the main use.
          codeNode.textContent = r.code.slice(0, 3) + " " + r.code.slice(3);
        },
        function () {
          codeNode.textContent = "(invalid key)";
        }
      );
    }
    tick();
    totpTimer = setInterval(tick, 1000);

    return el("div", { class: "field" }, [
      el("div", { class: "field-label", text: "Verification code" }),
      el("div", { class: "field-body" }, [codeNode, bar, timeNode, copyBtn])
    ]);
  }

  // The entry the view modal is showing. Recovery-code tick-offs mutate this
  // object and put() the result, so rapid ticks accumulate on one base even
  // before loadEntries refreshes the entries array.
  var viewEntry = null;

  // Recovery codes: masked as a block until the section's reveal toggle is
  // pressed; each code has a tick-off checkbox (used codes render struck
  // through) and its own copy button. Ticking is a genuine edit — the entry
  // re-encrypts and syncs like any other change.
  function recoverySection(entry) {
    var codes = entry.recovery || [];
    if (!codes.length) return null;
    var rows = codes.map(function (r, i) {
      var box = el("input", {
        type: "checkbox",
        class: "form-check-input",
        "data-rc-toggle": String(i),
        "aria-label": "Mark recovery code as used"
      });
      box.checked = !!r.used;
      return el("div", { class: "rc-row" + (r.used ? " rc-row-used" : "") }, [
        box,
        el("span", { class: "rc-code", text: r.code }),
        el("button", {
          class: "icon-btn",
          type: "button",
          "data-rc-copy": String(i),
          "aria-label": "Copy recovery code",
          text: "⧉"
        })
      ]);
    });
    return el("div", { class: "field", id: "rc-section" }, [
      el("div", { class: "field-label rc-head" }, [
        el("span", { class: "rc-count", text: rcCountText(codes) }),
        el("button", {
          class: "icon-btn",
          type: "button",
          "data-rc-reveal": "1",
          "aria-label": "Show recovery codes",
          text: "👁"
        })
      ]),
      el("div", { class: "rc-list" }, rows)
    ]);
  }

  function rcCountText(codes) {
    var left = codes.filter(function (r) {
      return !r.used;
    }).length;
    return "Recovery codes — " + left + " of " + codes.length + " unused";
  }

  function toggleRecoveryUsed(i, box) {
    if (!viewEntry || !viewEntry.recovery || !viewEntry.recovery[i]) return;
    viewEntry.recovery[i].used = box.checked;
    box.closest(".rc-row").classList.toggle("rc-row-used", box.checked);
    var count = byId("modal-card").querySelector(".rc-count");
    if (count) count.textContent = rcCountText(viewEntry.recovery);
    Vault.put(entryFields(viewEntry));
  }

  // The full payload rebuilt from a decrypted entry, for writes made outside
  // the edit form (recovery tick-offs). Must list every payload field: put()
  // drops anything missing.
  function entryFields(e) {
    return {
      id: e.id,
      created: e.created,
      title: e.title,
      username: e.username,
      password: e.password,
      url: e.url,
      notes: e.notes,
      critical: e.critical,
      totp: e.totp,
      recovery: e.recovery
    };
  }

  function openModalView(entry) {
    var card = byId("modal-card");
    card.innerHTML = "";
    stopTotp(); // switching entries must not leave the old entry's timer running
    card.dataset.mode = "view";
    card.dataset.id = entry.id;
    viewEntry = entry;

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
      entry.totp ? totpRow(entry.totp) : null,
      recoverySection(entry),
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

  // Secrets are masked against shoulder surfing with the same CSS the view
  // modal uses (-webkit-text-security on a type="text" input) rather than
  // type="password": browser save-password/autofill heuristics key on the
  // input type, and a real password field here would invite the browser to
  // capture vault entries into its own (cloud-synced) password store.
  function maskedField(name, labelText, value) {
    var input = el("input", {
      class: "form-input masked",
      type: "text",
      name: name,
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
      "aria-label": "Show " + labelText.toLowerCase(),
      text: "👁"
    });
    return el("div", { class: "form-row" }, [
      el("span", { class: "form-label", text: labelText }),
      el("div", { class: "sync-row" }, [input, toggle])
    ]);
  }

  // Recovery codes edit as plain lines, one code per line. Used/unused state
  // isn't shown or edited here; saveFromForm carries each code's used flag
  // across by exact string match, so editing the list never resets ticks.
  function recoveryEditField(codes) {
    var ta = el("textarea", {
      class: "form-input masked",
      name: "recovery",
      rows: "4",
      autocomplete: "off",
      spellcheck: "false",
      autocorrect: "off",
      autocapitalize: "off",
      placeholder: "One code per line"
    });
    ta.value = (codes || [])
      .map(function (r) {
        return r.code;
      })
      .join("\n");
    var toggle = el("button", {
      class: "icon-btn",
      type: "button",
      "data-reveal-input": "1",
      "aria-label": "Show recovery codes",
      text: "👁"
    });
    return el("div", { class: "form-row" }, [
      el("span", { class: "form-label", text: "Recovery codes (2FA)" }),
      el("div", { class: "sync-row" }, [ta, toggle])
    ]);
  }

  // The authenticator field is a maskedField plus, when a camera exists, a
  // scan link (handled by delegation on the modal — see data-scan-totp).
  function totpField(value) {
    var row = maskedField("totp", "Authenticator key (2FA)", value);
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      row.appendChild(
        el("button", {
          class: "form-scan-link",
          type: "button",
          "data-scan-totp": "1",
          text: "Scan the site's QR code with the camera"
        })
      );
    }
    return row;
  }

  function openModalEdit(entry) {
    entry = entry || {};
    var card = byId("modal-card");
    card.innerHTML = "";
    stopTotp(); // view -> edit replaces the card; the code row's timer goes with it
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
      maskedField("password", "Password", entry.password),
      // The site's 2FA setup key: bare base32, a pasted otpauth:// link
      // (Totp.normalize sorts it out on save), or — where a camera exists —
      // scanned from the site's enrolment QR via the shared scanner.
      totpField(entry.totp),
      recoveryEditField(entry.recovery),
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
    // A bad authenticator key blocks the save: storing it would render a
    // wrong code every 30s, which looks like the site's fault, not a typo.
    var totp;
    try {
      totp = Totp.normalize(form.totp.value);
    } catch (err) {
      toast(err.message);
      return;
    }
    // Recovery codes: one per line. Each code's used flag survives the edit
    // by exact string match against the previous list; new codes start
    // unused, removed lines drop their flag with them.
    var prevRec = (existing && existing.recovery) || [];
    var recovery = form.recovery.value
      .split("\n")
      .map(function (s) {
        return s.trim();
      })
      .filter(Boolean)
      .map(function (code) {
        var prev = prevRec.filter(function (r) {
          return r.code === code;
        })[0];
        return { code: code, used: !!(prev && prev.used) };
      });
    var fields = {
      id: id || undefined,
      created: existing ? existing.created : undefined,
      title: form.title.value.trim(),
      username: form.username.value.trim(),
      password: form.password.value,
      url: url,
      notes: form.notes.value,
      critical: form.critical.checked,
      totp: totp,
      recovery: recovery
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
    stopTotp();
    viewEntry = null;
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

  // wipe: overwrite the clipboard after the configured delay (passwords and
  // recovery codes — long-lived secrets; TOTP codes expire on their own).
  //
  // writeText only resolves while the document has focus, and copying a
  // password exists so the user can leave and paste it — so the timer nearly
  // always fires on a backgrounded tab, where the wipe is refused. The wipe is
  // therefore a *due time*, not a one-shot timeout: whichever comes later, the
  // timer or the next return to the app, performs it. A user who never comes
  // back keeps the secret on the clipboard; no page API can reach it from a
  // tab that isn't focused. The extension's offscreen document can, and does.
  function wipeClipboard() {
    if (!clipWipeDue || Date.now() < clipWipeDue) return;
    if (!document.hasFocus()) return; // retried on the focus/visibility events
    clipWipeDue = 0;
    // Can't verify the clipboard is still ours without a read prompt, so this
    // overwrites whatever is there once the delay has run.
    navigator.clipboard.writeText("").catch(function () {});
  }

  function copyValue(value, wipe, label) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(value).then(function () {
      var ms = clipClearMs();
      clearTimeout(clipTimer);
      if (wipe && ms > 0) {
        toast((label || "Password") + " copied — clears in " + ms / 1000 + "s");
        clipWipeDue = Date.now() + ms;
        clipTimer = setTimeout(wipeClipboard, ms);
      } else {
        // This copy already overwrote whatever was owed a wipe.
        clipWipeDue = 0;
        toast("Copied");
      }
    });
  }

  window.addEventListener("focus", wipeClipboard);
  document.addEventListener("visibilitychange", wipeClipboard);

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
      var tok = byId("sync-token");
      if (tok) tok.value = Sync.getToken();
      var st = byId("sync-status");
      if (st) st.textContent = Sync.getStatus().message || "";
      var vid = byId("vault-id");
      if (vid) vid.value = Sync.getVaultId();
      var sc = byId("setup-code");
      if (sc) sc.value = Sync.getVaultId() ? Sync.makeSetupCode() : "";
      // A fragment swap replaced any QR that was showing; drop its object URL.
      hideSetupQR();
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
      var inp = revealInput.parentNode.querySelector("input, textarea");
      if (inp) {
        var showNow = inp.classList.contains("masked");
        inp.classList.toggle("masked", !showNow);
        forceTextRepaint(inp);
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
      forceTextRepaint(span);
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
    var scanTotp = e.target.closest("[data-scan-totp]");
    if (scanTotp) {
      startTotpScan();
      return;
    }
    var rcToggle = e.target.closest("[data-rc-toggle]");
    if (rcToggle) {
      toggleRecoveryUsed(parseInt(rcToggle.getAttribute("data-rc-toggle"), 10), rcToggle);
      return;
    }
    var rcCopy = e.target.closest("[data-rc-copy]");
    if (rcCopy) {
      var rci = parseInt(rcCopy.getAttribute("data-rc-copy"), 10);
      if (viewEntry && viewEntry.recovery && viewEntry.recovery[rci]) {
        // Wipe like a password: unlike a TOTP code, a recovery code doesn't
        // expire on its own.
        copyValue(viewEntry.recovery[rci].code, true, "Recovery code");
      }
      return;
    }
    var rcReveal = e.target.closest("[data-rc-reveal]");
    if (rcReveal) {
      var sec = byId("rc-section");
      var revealed = sec.classList.toggle("rc-revealed");
      var rcCodes = sec.querySelectorAll(".rc-code");
      for (var rcn = 0; rcn < rcCodes.length; rcn++) {
        forceTextRepaint(rcCodes[rcn]);
      }
      rcReveal.textContent = revealed ? "🙈" : "👁";
      rcReveal.setAttribute(
        "aria-label",
        revealed ? "Hide recovery codes" : "Show recovery codes"
      );
      return;
    }
    var copyTotp = e.target.closest("[data-copy-totp]");
    if (copyTotp) {
      // No clipboard wipe: the code expires on its own in <=30s, and wiping
      // it mid-login while the user tabs over to the site is pure annoyance.
      if (totpCode) copyValue(totpCode, false);
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
  // Typing in a highlighted field is the fix, so drop the highlight on the
  // first keystroke rather than making the user re-submit to clear it.
  byId("lock-screen").addEventListener("input", function (e) {
    clearInvalid(e.target);
  });
  byId("create-form").addEventListener("submit", handleCreate);
  byId("unlock-form").addEventListener("submit", handleUnlock);
  byId("connect-form").addEventListener("submit", handleConnect);
  byId("connect-create").addEventListener("click", handleConnectCreate);
  byId("connect-scan").addEventListener("click", startConnectScan);
  byId("scan-cancel").addEventListener("click", stopScan);
  byId("create-restore").addEventListener("click", openRestore);
  byId("connect-restore").addEventListener("click", openRestore);
  byId("restore-file").addEventListener("change", handleRestoreFile);
  byId("welcome-continue").addEventListener("click", afterUnlock);
  byId("welcome-copy").addEventListener("click", function () {
    if (window.Sync) copyValue(Sync.getVaultId(), false);
  });
  // Vault picker: switch which vault the unlock prompt targets. Everything
  // here happens locked, so switching is only a matter of re-pointing the
  // modules and the manifest at the chosen vault.
  byId("unlock-switch").addEventListener("click", function () {
    showLock("picker");
  });
  byId("picker-add").addEventListener("click", function () {
    showLock("connect");
  });
  byId("connect-back").addEventListener("click", function () {
    showLock("picker");
  });
  byId("picker-list").addEventListener("click", function (e) {
    var b = e.target.closest("[data-vault-id]");
    if (!b) return;
    // Cross-vault state must not leak: hadEntries feeds the "key changed
    // under us" lock-loop guard in loadEntries and describes the PREVIOUS
    // vault's session.
    hadEntries = false;
    Sync.selectVault(b.getAttribute("data-vault-id"));
    if (window.App) App.refreshVaultUI();
    showLock("unlock");
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
      // The base32 key, not a code: losing it locks you out even with the
      // password, which is exactly what this sheet exists to survive.
      field(rows, "Authenticator key", e.totp);
      if (e.recovery && e.recovery.length) {
        // All codes, with used ones marked — on paper a code crossed off in
        // the app is still legible, and the mark says why it may not work.
        field(
          rows,
          "Recovery codes",
          e.recovery
            .map(function (r) {
              return r.code + (r.used ? "  (used)" : "");
            })
            .join("\n")
        );
      }
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

  // Settings setup-code QR: server-rendered PNG (see sync.js fetchSetupQR),
  // shown via an object URL because a plain <img src> can't carry the auth
  // header. The QR displays the token, so it's shown on demand and torn down
  // on toggle, fragment swap, and lock.
  var setupQrUrl = null;

  function hideSetupQR() {
    var box = byId("setup-qr");
    if (box) {
      box.hidden = true;
      box.innerHTML = "";
    }
    if (setupQrUrl) {
      URL.revokeObjectURL(setupQrUrl);
      setupQrUrl = null;
    }
  }

  function toggleSetupQR() {
    var box = byId("setup-qr");
    if (!box) return;
    if (!box.hidden) {
      hideSetupQR();
      return;
    }
    if (!window.Sync || !Sync.getVaultId()) return;
    Sync.fetchSetupQR()
      .then(function (blob) {
        hideSetupQR();
        setupQrUrl = URL.createObjectURL(blob);
        var img = document.createElement("img");
        img.src = setupQrUrl;
        img.alt = "Setup code as a QR code";
        box.appendChild(img);
        box.hidden = false;
      })
      .catch(function () {
        toast("Couldn't get the QR code — check the server connection.");
      });
  }

  // Settings "Remove from this device": delete the ACTIVE vault's database
  // and config from this browser, then land on the next vault's lock gate.
  // Removing the LAST vault escalates to the full teardown — all localStorage
  // (UI prefs included), service worker + caches — back to the first-run
  // gate. That is the buildable half of "uninstall": no web API can remove an
  // installed icon, but the icon without the data is an empty shell.
  function removeFromDevice() {
    var last = !window.Sync || Sync.listVaults().length <= 1;
    confirmDialog({
      title: "Remove vault from this device?",
      message:
        "This vault is deleted from this browser only" +
        (last ? "" : " — other vaults on this device are untouched") +
        ". Unsynced changes are lost for good. The app icon stays until " +
        "you remove it from your browser or home screen.",
      confirmText: "Remove",
      danger: true
    }).then(function (ok) {
      if (!ok) return;
      if (window.Sync) Sync.stop();
      var id = window.Sync ? Sync.getVaultId() : "";
      Vault.wipeLocal()
        .then(function () {
          if (window.Sync) Sync.removeVault(id);
          var rest = window.Sync ? Sync.listVaults() : [];
          if (rest.length) {
            // Vaults remain: select the next one and reload into its gate
            // (the reload also re-points the manifest and title cleanly).
            Sync.selectVault(rest[0]);
            location.replace("/");
            return;
          }
          try {
            localStorage.clear();
          } catch (e) {
            /* ignore */
          }
          var jobs = [];
          if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
            jobs.push(
              navigator.serviceWorker.getRegistrations().then(function (regs) {
                return Promise.all(
                  regs.map(function (r) {
                    return r.unregister();
                  })
                );
              })
            );
          }
          if (window.caches) {
            jobs.push(
              caches.keys().then(function (keys) {
                return Promise.all(
                  keys.map(function (k) {
                    return caches.delete(k);
                  })
                );
              })
            );
          }
          // Best effort on SW/caches: even if one fails, the vault and config
          // are already gone, so always land back on the fresh gate.
          return Promise.all(jobs)
            .catch(function () {})
            .then(function () {
              location.reload();
            });
        });
    });
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
    if (e.target.closest("#sync-token-reveal")) {
      var tokEl = byId("sync-token");
      var showing = tokEl.type === "text";
      tokEl.type = showing ? "password" : "text";
      e.target.closest("#sync-token-reveal").textContent = showing ? "Show" : "Hide";
      return;
    }
    // No clipboard wipe: the token gets pasted on another device (possibly via
    // a cross-device clipboard, minutes later), and it's already plaintext in
    // localStorage — the wipe would cost the transfer more than it protects.
    if (e.target.closest("#sync-token-copy")) {
      if (window.Sync) copyValue(Sync.getToken(), false);
      return;
    }
    if (e.target.closest("#setup-code-copy")) {
      if (window.Sync && Sync.getVaultId()) copyValue(Sync.makeSetupCode(), false);
      return;
    }
    if (e.target.closest("#setup-qr-btn")) {
      toggleSetupQR();
      return;
    }
    if (e.target.closest("#wipe-device")) {
      removeFromDevice();
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
      "It restores the vault the backup was exported from — which may not " +
      "be the vault currently open — replacing that vault's contents on " +
      "this device. The backup's entries also overwrite the matching ones " +
      "on the server and your other devices (entries that exist only on " +
      "the server are kept).\n\nThis can't be undone.";
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
            // importVault switched to the backup's own vault; register it so
            // the restored device rejoins that server namespace and keeps
            // syncing with any surviving devices instead of forking.
            hadEntries = false; // the lock-loop guard describes the old vault
            if (window.Sync) Sync.setVaultId(res.vaultId);
            if (window.App) App.refreshVaultUI();
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
        show(byId("change-strength"), false); // fields were just cleared
        settingsMsg("change-pw-msg", "Master password changed.", false);
      } else {
        settingsMsg("change-pw-msg", "Current password is incorrect.", true);
      }
    });
  });

  // Full re-encrypt (compromise recovery): fresh vault key + new master
  // password, every entry re-encrypted. Guarded by a danger confirm; refuses
  // while conflicts are unresolved (their stashed server versions are old-key
  // ciphertext and would become undecryptable mid-resolution).
  document.body.addEventListener("submit", function (e) {
    if (e.target.id !== "reencrypt-form") return;
    e.preventDefault();
    var f = e.target;
    if (f["new"].value.length < 12) {
      settingsMsg(
        "reencrypt-msg",
        "New password must be at least 12 characters — a few random words make a strong passphrase.",
        true
      );
      return;
    }
    if (f["new"].value !== f.new2.value) {
      settingsMsg("reencrypt-msg", "New passwords don't match.", true);
      return;
    }
    Vault.conflictCount().then(function (n) {
      if (n > 0) {
        settingsMsg(
          "reencrypt-msg",
          "Resolve the pending sync " + (n > 1 ? "conflicts" : "conflict") + " first, then re-encrypt.",
          true
        );
        return;
      }
      confirmDialog({
        title: "Re-encrypt the whole vault?",
        message:
          "Every entry will be re-encrypted with a fresh vault key, locked by " +
          "your new master password.\n\n" +
          "• Your other devices will need the new master password.\n" +
          "• Old backup files still open with the OLD password — export a new " +
          "backup afterwards and destroy the old ones.",
        confirmText: "Re-encrypt",
        danger: true
      }).then(function (ok) {
        if (!ok) return;
        settingsMsg("reencrypt-msg", "Re-encrypting…", false);
        Vault.reencrypt(f.old.value, f["new"].value).then(
          function (count) {
            if (count === false) {
              settingsMsg("reencrypt-msg", "Current password is incorrect.", true);
              return;
            }
            f.reset();
            show(byId("reenc-strength"), false);
            settingsMsg(
              "reencrypt-msg",
              "Done — " + count + (count === 1 ? " entry" : " entries") +
                " re-encrypted with a fresh key. Export a new backup, and unlock " +
                "other devices with the new password.",
              false
            );
          },
          function (err) {
            settingsMsg(
              "reencrypt-msg",
              (err && err.message) || "Re-encrypt failed — the vault is unchanged.",
              true
            );
          }
        );
      });
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
