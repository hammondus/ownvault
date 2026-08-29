(function () {
  "use strict";

  var STORAGE_KEY = "menuBtnPos";
  var SCHEME_KEY = "colorScheme";
  var PIN_KEY = "menuPinned";
  var DRAG_THRESHOLD = 8; // px of movement before a press becomes a drag
  var DOUBLE_TAP_MS = 350; // two taps within this = double-tap (pin toggle)

  /* ==================== Colour scheme ==================== */
  // Two schemes, chosen on the Settings screen and persisted. The colors
  // themselves live in CSS (body.theme-classic overrides the variables);
  // the values here only feed the theme-color meta so the browser chrome
  // matches. "midnight" must stay in step with manifest.webmanifest.

  var SCHEMES = {
    midnight: "#0a1f3b",
    classic: "#1a4080"
  };

  function savedScheme() {
    var s = null;
    try {
      s = localStorage.getItem(SCHEME_KEY);
    } catch (e) { /* ignore */ }
    return SCHEMES[s] ? s : "midnight";
  }

  function applyScheme(name) {
    if (!SCHEMES[name]) name = "midnight";
    document.body.classList.toggle("theme-classic", name === "classic");
    document
      .querySelector('meta[name="theme-color"]')
      .setAttribute("content", SCHEMES[name]);
  }

  applyScheme(savedScheme());

  /* ==================== PWA / vault name ==================== */
  // A short nickname per vault ("Home", "Work"). It labels the installed app
  // icon, the lock screen, and the vault picker. This is the plaintext
  // on-device mirror of the vault's encrypted name — never sent to a sync
  // server, so the zero-knowledge property holds even on a shared public
  // server. One hostname can hold several vaults, so the key is suffixed per
  // vault; re-applying the active vault's name on every load sidesteps the
  // timing quirk where the browser captures the manifest name before the
  // user has typed one.

  var VAULT_NAME_KEY = "vaultName";
  var manifestBlobUrl = null;

  function nameKey(id) {
    return VAULT_NAME_KEY + ":" + id;
  }

  // Name of the given vault, defaulting to the active one; "" when there is
  // no such name (or no active vault). The id argument lets the lock-gate
  // picker label vaults other than the active one.
  function getVaultName(id) {
    id = id || (window.Sync ? Sync.getVaultId() : "");
    if (!id) return "";
    try {
      return localStorage.getItem(nameKey(id)) || "";
    } catch (e) {
      return "";
    }
  }

  // Running as an installed app rather than a browser tab. Chromium reports
  // this through display-mode; iOS Safari has its own flag. All three
  // installed display modes count — a window-controls-overlay or minimal-ui
  // install is as installed as a standalone one.
  function isStandalone() {
    var mq = window.matchMedia;
    return (
      (!!mq &&
        (mq("(display-mode: standalone)").matches ||
          mq("(display-mode: minimal-ui)").matches ||
          mq("(display-mode: window-controls-overlay)").matches ||
          mq("(display-mode: fullscreen)").matches)) ||
      window.navigator.standalone === true
    );
  }

  function setAppleTitle(value) {
    // iOS ignores the manifest for naming; the home-screen title comes from this
    // meta (falling back to <title>). Create it lazily — index.html doesn't ship
    // one so the default install stays "Own Vault".
    var m = document.querySelector('meta[name="apple-mobile-web-app-title"]');
    if (!m) {
      m = document.createElement("meta");
      m.setAttribute("name", "apple-mobile-web-app-title");
      document.head.appendChild(m);
    }
    m.setAttribute("content", value);
  }

  // Option A: point <link rel="manifest"> at a client-generated manifest that
  // carries the vault name. The name never leaves the device. Icons/URLs must be
  // ABSOLUTE — a blob: URL has no useful base to resolve "/icons/..." against.
  // id + start_url are constant PER VAULT: a rename still relabels the same
  // app (no duplicate install), while each vault installs as its own app,
  // launching at /?vault=<id> so the icon reopens the right vault.
  function setBlobManifest(link, name) {
    var origin = location.origin;
    var vaultUrl =
      origin +
      "/?vault=" +
      encodeURIComponent(window.Sync ? Sync.getVaultId() : "");
    var manifest = {
      id: vaultUrl,
      name: name,
      short_name: name,
      description:
        "Own Vault: an offline-first, end-to-end encrypted password manager.",
      start_url: vaultUrl,
      scope: origin + "/",
      display: "standalone",
      background_color: "#f4f6f8",
      theme_color: SCHEMES[savedScheme()],
      icons: [
        { src: origin + "/icons/lock.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
        { src: origin + "/icons/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
        { src: origin + "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
        { src: origin + "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" }
      ]
    };
    try {
      var blob = new Blob([JSON.stringify(manifest)], {
        type: "application/manifest+json"
      });
      var url = URL.createObjectURL(blob);
      if (manifestBlobUrl) URL.revokeObjectURL(manifestBlobUrl);
      manifestBlobUrl = url;
      link.href = url;
    } catch (e) {
      // Blob manifest unsupported: leave the static manifest (default name).
    }
  }

  // Reflect the vault name in the installed-app name (manifest) and the iOS
  // home-screen title. Called at startup and whenever the name changes. The
  // manifest is generated entirely client-side (a blob: URL) so the name never
  // reaches the server — keeping zero-knowledge on shared/public servers.
  function applyPwaName() {
    var name = getVaultName();
    setAppleTitle(name || "Own Vault");
    var link = document.querySelector('link[rel="manifest"]');
    var vid = window.Sync ? Sync.getVaultId() : "";
    if (!link || !vid) return; // no vault yet -> keep the static manifest
    // Even an unnamed vault gets the blob manifest: two vaults must carry
    // distinct manifest ids or installing the second replaces the first.
    setBlobManifest(link, name || "Own Vault");
  }

  // An installed vault icon launches at /?vault=<id> (its manifest's
  // start_url). Adopt that vault for this tab, then strip the parameter —
  // like the setup-code fragment, it must not linger in the URL or the
  // history entry. An id not on this device (an icon outliving a removed
  // vault) is ignored and the tab stays on the last-used vault. Runs before
  // applyPwaName so the manifest reflects the launched vault.
  (function () {
    var m = /[?&]vault=([^&]+)/.exec(location.search);
    if (!m) return;
    var id = "";
    try {
      id = decodeURIComponent(m[1]);
    } catch (e) {
      /* malformed escape: treat as unknown */
    }
    if (id && window.Sync && Sync.listVaults().indexOf(id) >= 0) {
      Sync.selectVault(id);
    }
    if (window.history && history.replaceState) {
      history.replaceState(null, "", location.pathname + location.hash);
    }
  })();

  applyPwaName();

  var btn = document.getElementById("menu-btn");
  var nav = document.getElementById("nav");
  var overlay = document.getElementById("overlay");
  var main = document.getElementById("main");
  var navLinks = Array.prototype.slice.call(
    document.querySelectorAll(".nav-link")
  );

  /* ==================== Nav open / close ==================== */

  function isNavOpen() {
    return nav.classList.contains("open");
  }

  function openNav() {
    nav.classList.add("open");
    // A pinned drawer coexists with the content (which moves aside), so no
    // dimming overlay — that's what makes pinning useful on a large screen.
    if (!isPinned()) overlay.classList.add("visible");
    btn.setAttribute("aria-expanded", "true");
    btn.setAttribute("aria-label", "Close menu");
  }

  function closeNav() {
    nav.classList.remove("open");
    overlay.classList.remove("visible");
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-label", "Open menu");
  }

  function toggleNav() {
    isNavOpen() ? closeNav() : openNav();
  }

  /* Pinning: double-tap the hamburger to keep the drawer open (persisted).
     Only honoured on screens wide enough for the content to move aside
     (min-width 900px, matching the CSS) — on a phone a pinned drawer would
     sit over the content with nothing dimming it. */

  var pinQuery = window.matchMedia("(min-width: 900px)");

  function isPinned() {
    return document.body.classList.contains("nav-pinned");
  }

  function setPinned(on) {
    if (on && !pinQuery.matches) return; // too narrow — ignore the request
    document.body.classList.toggle("nav-pinned", on);
    try {
      if (on) localStorage.setItem(PIN_KEY, "1");
      else localStorage.removeItem(PIN_KEY);
    } catch (e) { /* pin works, just won't persist */ }
    if (on) {
      openNav();
      overlay.classList.remove("visible"); // in case it was already showing
    } else {
      closeNav();
    }
  }

  // Restore the pin (silently ignored on narrow screens), and drop it if the
  // window later shrinks below the threshold — otherwise the drawer would
  // cover the content with no way to dismiss it by tapping outside.
  try {
    if (localStorage.getItem(PIN_KEY) === "1") setPinned(true);
  } catch (e) { /* ignore */ }
  var onPinQuery = function () {
    if (!pinQuery.matches && isPinned()) setPinned(false);
  };
  if (pinQuery.addEventListener) pinQuery.addEventListener("change", onPinQuery);
  else pinQuery.addListener(onPinQuery); // older Safari

  overlay.addEventListener("click", closeNav);

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && isNavOpen() && !isPinned()) closeNav();
  });

  /* ==================== Routing glue around htmx ==================== */
  // htmx does the fetching, swapping, and history. This glue closes the
  // drawer on navigation and keeps the title + active link in sync.

  function linkForPath(path) {
    for (var i = 0; i < navLinks.length; i++) {
      if (navLinks[i].getAttribute("hx-push-url") === path) return navLinks[i];
    }
    return null;
  }

  function syncUI() {
    var link = linkForPath(location.pathname) || linkForPath("/");
    navLinks.forEach(function (a) {
      a.classList.toggle("active", a === link);
    });
    // In a tab the vault name is the only thing telling one vault's tab from
    // another's, so it belongs in the title. An installed window already shows
    // the manifest name in its own chrome and the browser prepends it to
    // document.title, so appending it there reads "Home - Passwords - Home".
    var name = isStandalone() ? "" : getVaultName() || "Own Vault";
    document.title = name ? link.dataset.title + " - " + name : link.dataset.title;
  }

  // The drawer slides closed while the new content swaps in underneath —
  // no page reload, so the animation plays fully. A pinned drawer stays put.
  navLinks.forEach(function (a) {
    a.addEventListener("click", function () {
      if (!isPinned()) closeNav();
    });
  });

  document.body.addEventListener("htmx:pushedIntoHistory", syncUI);
  window.addEventListener("popstate", syncUI); // back/forward restores

  // The Go server returns this same shell for every app route; load the
  // fragment matching the current URL.
  var initial = linkForPath(location.pathname) || linkForPath("/");
  htmx.ajax("GET", initial.getAttribute("hx-get"), {
    target: "#main",
    swap: "innerHTML"
  });
  syncUI();

  /* ==================== Draggable button ==================== */

  // Position is stored as fractions of the available space so it stays
  // proportionally in place across screen sizes and orientation changes.
  var drag = null; // { pointerId, startX, startY, offsetX, offsetY, moved }

  function maxLeft() {
    return window.innerWidth - btn.offsetWidth;
  }

  function maxTop() {
    return window.innerHeight - btn.offsetHeight;
  }

  function clamp(v, min, max) {
    return Math.min(Math.max(v, min), max);
  }

  function setPosition(left, top) {
    left = clamp(left, 0, maxLeft());
    top = clamp(top, 0, maxTop());
    btn.style.left = left + "px";
    btn.style.top = top + "px";
  }

  function savePosition() {
    var rect = btn.getBoundingClientRect();
    var pos = {
      fx: maxLeft() > 0 ? rect.left / maxLeft() : 0,
      fy: maxTop() > 0 ? rect.top / maxTop() : 0
    };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(pos));
    } catch (e) {
      /* storage unavailable (private mode etc.) — position just won't persist */
    }
  }

  function restorePosition() {
    var raw = null;
    try {
      raw = localStorage.getItem(STORAGE_KEY);
    } catch (e) { /* ignore */ }
    if (!raw) return;
    try {
      var pos = JSON.parse(raw);
      if (typeof pos.fx === "number" && typeof pos.fy === "number") {
        setPosition(pos.fx * maxLeft(), pos.fy * maxTop());
      }
    } catch (e) { /* corrupt value — fall back to CSS default */ }
  }

  btn.addEventListener("pointerdown", function (e) {
    if (drag) return;
    var rect = btn.getBoundingClientRect();
    drag = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      offsetX: e.clientX - rect.left,
      offsetY: e.clientY - rect.top,
      moved: false
    };
    btn.setPointerCapture(e.pointerId);
  });

  btn.addEventListener("pointermove", function (e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    if (!drag.moved) {
      var dx = e.clientX - drag.startX;
      var dy = e.clientY - drag.startY;
      if (Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
      drag.moved = true;
      btn.classList.add("dragging");
    }
    setPosition(e.clientX - drag.offsetX, e.clientY - drag.offsetY);
  });

  var lastTapAt = 0;
  var lastTapUnpinned = false;

  function endDrag(e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    var wasDrag = drag.moved;
    drag = null;
    btn.classList.remove("dragging");
    if (wasDrag) {
      savePosition();
      return;
    }
    if (e.type !== "pointerup") return;
    // A press without movement is a tap. Double-tap pins the drawer open;
    // while pinned, any tap releases it. The first tap of a double-tap has
    // already acted by the time the second arrives, so the second must know
    // what the first did: after open, it pins; after an unpin, it swallows
    // (or the double-tap that released a pin would immediately re-pin).
    var now = Date.now();
    var isDoubleTap = now - lastTapAt < DOUBLE_TAP_MS;
    lastTapAt = now;
    if (isDoubleTap) {
      if (!lastTapUnpinned) setPinned(true);
      lastTapUnpinned = false;
    } else if (isPinned()) {
      setPinned(false);
      lastTapUnpinned = true;
    } else {
      toggleNav();
      lastTapUnpinned = false;
    }
  }

  btn.addEventListener("pointerup", endDrag);
  btn.addEventListener("pointercancel", endDrag);

  // The tap already toggles the nav via pointerup; swallow the click that
  // follows so it doesn't toggle a second time on some browsers.
  btn.addEventListener("click", function (e) {
    e.preventDefault();
  });

  // Keep the button on screen and proportionally placed on resize/rotation.
  window.addEventListener("resize", restorePosition);

  restorePosition();

  /* ==================== Page-specific hooks ==================== */
  // Screen content is swapped in and out, so bind through delegation on
  // <main> rather than to elements that may not exist yet.

  main.addEventListener("click", function (e) {
    if (e.target.id === "reset-btn") {
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch (err) { /* ignore */ }
      btn.style.left = "";
      btn.style.top = "";
    }
  });

  main.addEventListener("change", function (e) {
    if (e.target.id === "scheme-select") {
      try {
        localStorage.setItem(SCHEME_KEY, e.target.value);
      } catch (err) { /* ignore — scheme applies but won't persist */ }
      applyScheme(e.target.value);
    }
  });

  // Reflect the saved scheme in the picker whenever the Settings fragment
  // arrives (fresh fetch or back/forward history restore).
  function syncSchemeControl() {
    var sel = document.getElementById("scheme-select");
    if (sel) sel.value = savedScheme();
  }

  document.body.addEventListener("htmx:afterSwap", syncSchemeControl);
  document.body.addEventListener("htmx:historyRestore", syncSchemeControl);

  /* ==================== Offline feedback ==================== */
  // htmx fails silently when a fragment request dies (e.g. offline with no
  // service worker) — surface that instead of appearing to do nothing.

  var toastTimer = null;

  function showToast(msg) {
    var toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.classList.add("visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      toast.classList.remove("visible");
    }, 3000);
  }

  document.body.addEventListener("htmx:sendError", function () {
    showToast(
      navigator.onLine
        ? "Couldn't reach the server."
        : "You're offline and this screen isn't cached."
    );
  });

  document.body.addEventListener("htmx:responseError", function (e) {
    showToast("Server error " + e.detail.xhr.status);
  });

  // Diagnostics shown on the About screen (present only in that fragment).
  function fillDiagnostics() {
    var net = document.getElementById("net-status");
    var sw = document.getElementById("sw-status");
    if (net) {
      net.textContent =
        netOnline === false
          ? "offline"
          : netOnline === true
            ? "online — server reachable"
            : navigator.onLine
              ? "online"
              : "offline";
    }
    if (!sw) return;
    if (!("serviceWorker" in navigator)) {
      sw.textContent = "no — this browser doesn't support service workers";
    } else if (!window.isSecureContext) {
      sw.textContent =
        "no — not served over HTTPS (or localhost), so the service worker cannot register";
    } else if (navigator.serviceWorker.controller) {
      sw.textContent = "yes — service worker active, screens cached";
    } else {
      sw.textContent =
        "not yet — service worker registered but not controlling; reload the page once";
    }
  }

  document.body.addEventListener("htmx:afterSwap", fillDiagnostics);

  /* ==================== Reachability ==================== */
  // True reachability (not just "have a network"), driven by three signals
  // all funnelling into setNetworkState:
  //   1. the /events SSE connection — the server pings every 25s and the
  //      browser auto-reconnects, so connection state ≈ server reachability
  //   2. htmx request failures (successes prove nothing — see below)
  //   3. navigator.onLine — instant airplane-mode/wifi-off detection
  // body.offline reveals the ribbon (CSS); "Back online" toasts only fire
  // on an actual offline → online transition, never on initial load.

  var netOnline = null; // null until the first signal arrives

  function setNetworkState(online) {
    if (online === netOnline) return;
    var wasOffline = netOnline === false;
    netOnline = online;
    document.body.classList.toggle("offline", !online);
    fillDiagnostics();
    if (online && wasOffline) showToast("Back online");
  }

  var PING_INTERVAL_MS = 25000; // matches the server's ticker
  var lastPing = Date.now();

  var events = null;
  var sseRetryMs = 5000;

  function connectEvents() {
    var es = new EventSource("/events");
    events = es;
    es.onopen = function () {
      lastPing = Date.now();
      sseRetryMs = 5000;
      setNetworkState(true);
    };
    es.addEventListener("ping", function () {
      lastPing = Date.now();
      setNetworkState(true);
    });
    es.onerror = function () {
      // Fires on every failed auto-reconnect attempt too; dedup'd above.
      setNetworkState(false);
      // A non-200 response (e.g. the server's 503 at its SSE connection cap)
      // fatally CLOSEs the EventSource — per spec the browser never retries
      // it. Rebuild it ourselves with backoff, or reachability (and the
      // offline ribbon) would stay wrong for the rest of the session.
      if (events === es && es.readyState === EventSource.CLOSED) {
        setTimeout(connectEvents, sseRetryMs);
        sseRetryMs = Math.min(sseRetryMs * 2, 60000);
      }
    };
  }
  connectEvents();

  // Watchdog for silently dead connections (e.g. wifi up, internet down,
  // no TCP reset) where onerror never fires: two missed pings = offline.
  setInterval(function () {
    if (document.hidden) return;
    if (Date.now() - lastPing > PING_INTERVAL_MS * 2 + 10000) {
      setNetworkState(false);
    }
  }, 15000);

  // iOS suspends timers and the SSE connection in background tabs; on
  // return, give the reconnect a grace period instead of flashing offline.
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) lastPing = Date.now();
  });

  window.addEventListener("online", function () {
    setNetworkState(true); // optimistic; SSE corrects it if wrong
  });
  window.addEventListener("offline", function () {
    setNetworkState(false);
  });

  // Piggyback on htmx traffic — failures only. A successful response is NOT
  // evidence of reachability: offline, the service worker serves fragments
  // from cache as normal 200s, indistinguishable from the network. Recovery
  // detection belongs to the SSE connection alone.
  document.body.addEventListener("htmx:sendError", function () {
    setNetworkState(false);
  });

  setNetworkState(navigator.onLine);

  /* ==================== Service worker ==================== */

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js");
  }

  /* ==================== exports ==================== */
  // The vault name lives in the app shell (it owns the manifest link and
  // <title>); vaultui.js drives it from the create/settings screens.
  window.App = {
    getVaultName: getVaultName,
    isStandalone: isStandalone,
    setVaultName: function (name) {
      var id = window.Sync ? Sync.getVaultId() : "";
      if (id) {
        try {
          localStorage.setItem(nameKey(id), name || "");
        } catch (e) { /* ignore */ }
      }
      applyPwaName();
      syncUI(); // refresh the tab-title suffix immediately
    },
    // After a vault switch: re-point the manifest and title at the newly
    // active vault (vaultui calls this alongside Sync.selectVault).
    refreshVaultUI: function () {
      applyPwaName();
      syncUI();
    }
  };
})();
