---
name: verify
description: How to run and drive this PWA to verify changes end-to-end.
---

# Verifying changes to this PWA

## Launch

```sh
go run . -dev        # serves web/ from disk on :8080 (+ :8443 if certs/ exist)
```

Port 8080 already bound usually means the user's own dev server is running
(`lsof -nP -iTCP:8080 -sTCP:LISTEN`). In `-dev` mode it serves `web/` from
disk, so it already reflects working-tree edits — just drive it, don't kill it.

## Drive (browser surface)

No Playwright in the repo; install it in the session scratchpad:

```sh
cd $SCRATCHPAD && npm init -y && npm i playwright && npx playwright install chromium
```

Drive with a phone-ish viewport (390x780). Gotchas:

- The shell arrives with `<main>` empty; app.js fetches the initial fragment —
  wait for `#main .screen` before asserting anything.
- Navigate like a user: click `#menu-btn`, then a drawer link
  (`a[hx-push-url="/settings"]` etc.). The drawer close animation takes
  0.25s — screenshots right after navigation catch it mid-slide.
- Useful state to read: `body.classList`, computed styles of `.app-header` /
  `.menu-btn`, `meta[name="theme-color"]`, localStorage keys
  (`menuBtnPos`, `colorScheme`).

## Flows worth driving

- Drawer open/close + hamburger drag (position persists in localStorage).
- Fragment navigation + back/forward (htmx history; select/controls inside
  fragments must re-sync on `htmx:afterSwap` **and** `htmx:historyRestore`).
- Colour scheme switch on Settings (midnight/classic), persistence across
  reload, garbage localStorage value falls back to midnight.
- Offline behavior needs the service worker: localhost registers it, but
  `-dev` freshness vs cache means bump `VERSION` in `web/sw.js` when testing.
