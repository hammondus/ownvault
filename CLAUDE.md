# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands
This repo is a GitHub *template* for PWA apps with a hamburger menu. All
name-specific strings use the placeholder "My App" / `myapp`; the README's
"Using this template" section lists every file to touch when renaming for a
new project — keep that list up to date if you add another.
```sh
go run . -dev                 # development: serves web/ from disk, so edit + refresh (no rebuild)
go build -o myapp .      # production: single binary with web/ embedded via go:embed
./myapp -addr :3000      # default addr is :8080
```

There are no tests or linters configured. `web/` files are embedded at build
time, so changes to them require a rebuild unless running with `-dev`.

If `certs/cert.pem` + `certs/key.pem` exist (generated with mkcert for the
user's LAN IPs), the server also listens on HTTPS at `-tlsaddr` (default
`:8443`) — required for the service worker / PWA install on phones. See
README for the mkcert commands and one-time iPhone CA-trust steps.

## Architecture

PWA using the app-shell model: a Go static server, htmx for
navigation, and vanilla JS for UI behavior. No build step, no node_modules;
htmx 2.x is vendored at `web/js/htmx.min.js`.

**Routing spans three files that must stay consistent:**

- `main.go` serves any path that matches a real file under `web/`; every other
  path (`/dashboard`, `/profile`, ...) returns the shell `web/index.html`.
- Nav links in `web/index.html` carry `hx-get="/pages/<name>.html"` (the
  fragment htmx swaps into `<main>`) plus `hx-push-url="/<name>"` and
  `data-title`. The plain `href` is the no-JS fallback.
- `web/js/app.js` maps `location.pathname` back to a nav link by its
  `hx-push-url` value — on first load (to fetch the initial fragment, since
  the shell arrives with `<main>` empty) and on history changes (to sync
  `document.title` and the `.active` link).

Screens are fragments in `web/pages/*.html`, each a single
`<section class="screen">` root (the swap fade-in animation and htmx history
snapshots rely on this shape). Deliberately no full page loads: that's what
eliminates the flash between screens and lets the drawer's close animation
play over the incoming content.

**Adding a screen** takes three edits: create `web/pages/<name>.html`, add the
nav `<li>` in `web/index.html`, and add the fragment path to `PRECACHE` in
`web/sw.js` + bump its `VERSION`.

**app.js** also owns the drawer (open/close + overlay) and the draggable
hamburger button: pointer events, <8px movement = tap (toggles drawer),
otherwise drag; position persists in localStorage as *fractions* of available
space so it survives rotation/resize. Because screen content is swapped,
controls inside fragments (e.g. the settings reset button) must be bound via
event delegation on `#main`, never direct listeners at startup.

**Service worker** (`web/sw.js`) is network-first with cache fallback: online
always hits the Go server (dev stays fresh), offline serves from cache, with
all navigations falling back to the cached shell. It only registers on
localhost or HTTPS — phone testing uses the mkcert HTTPS listener above.

**Reachability / SSE**: `main.go` serves server-sent events at `/events`
(keepalive pings every 25s). The client (`app.js`) derives true reachability
from the EventSource connection state plus htmx request outcomes and
`navigator.onLine`, all funnelled through `setNetworkState` (drives the
offline ribbon via `body.offline`). Future push features should reuse this
stream: emit named events in the `/events` handler, listen in app.js. The
service worker deliberately bypasses `/events` (infinite response — caching
it would hang) and must keep doing so.

## Conventions

- There are two colour schemes, picked on the Settings screen and persisted
  in localStorage: "midnight" (`#0a1f3b`, the default) and "classic"
  (`#1a4080` bar + accent hamburger). The scheme colors live in `:root` /
  `body.theme-classic` in `web/css/style.css` and again in the `SCHEMES` map
  in `web/js/app.js` (which drives the `<meta name="theme-color">`); both
  must stay in step, and `web/manifest.webmanifest` `theme_color` must match
  the midnight default.
- `assets/logo.png` is a source asset, not served. The icons in
  `web/icons/` are derived from it with `sips` (resize to ~66% width, pad to
  square with white, flatten alpha via a JPEG round-trip — opaque + the
  maskable safe zone matter for Android/iOS).
- When a screen later needs live data, replace its static fragment with a Go
  handler that renders the same fragment HTML; the htmx side doesn't change.
- JS is written in ES5 style (`var`, function expressions) — match it.
