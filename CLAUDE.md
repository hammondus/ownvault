# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
# Own Vault

A password manager built on top of the PWA template app (see "PWA Template"
below). One master password unlocks a database of passwords. The PWA is the
primary client; the Go server is a zero-knowledge sync + hosting point.

## Client-side crypto (the core design rule)

All encryption and decryption happens in the browser via WebCrypto. The Go
server never sees plaintext or keys — it only ever stores and relays
ciphertext the client produced. That zero-knowledge property is a hard
requirement, not an implementation detail.

Keys are layered (key wrapping / envelope encryption, the Bitwarden/1Password
pattern):

- A random **vault key** (AES-GCM) is generated once and encrypts all
  entries.
- Master password → PBKDF2 → **wrapping key**, which encrypts only the vault
  key. The resulting **wrapped-key record** (wrapped vault key + PBKDF2 salt
  + iteration count) is one small piece of vault metadata — none of it is
  secret, and it must survive export/import and sync alongside the entries.
- Unlock = attempt to unwrap the vault key. A wrong master password is
  detected by AES-GCM authentication failure on that one record — immediate,
  unambiguous, and no separate password hash is stored anywhere.
- Changing the master password = re-wrap the vault key with the new wrapping
  key and atomically replace the wrapped-key record. One tiny write — no mass
  re-encryption of entries, so an interrupted password change can't leave the
  vault half-migrated across two keys.
- Caveat: re-wrapping protects against future guessing of the old password,
  but anyone who already copied the vault *and* knew the old password has the
  vault key forever. So alongside "change password", offer an explicit "full
  re-encrypt" (new vault key, every entry re-encrypted) for suspected
  compromise — that rare path is the only one that needs interruption-safe
  migration handling (e.g. keep both wrapped keys until every entry carries
  the new key's generation marker).

## Data model: per-entry encrypted records

The vault is NOT one encrypted blob. Each password entry is its own encrypted
record: `{id, ciphertext, updatedAt, deleted}` — deletes are tombstones so
they sync. The client encrypts each entry individually.

Per-entry granularity is what makes offline sync tractable: edits to
different entries on different devices merge silently; only a genuine
same-entry conflict needs human attention. The accepted trade-off is that the
server can see the number of entries and their update times (never contents).

## Client storage & backup

- Entries live in the browser's IndexedDB (not localStorage), always
  encrypted. Call `navigator.storage.persist()` to reduce eviction risk.
- Browser storage can still be cleared at any time (by the browser or the
  user clearing cache), so the UI reminds the user not to stay offline too
  long, and encrypted export/import to a file must work fully offline.
  Export/import ships first, before sync.
- **Restore semantics (merge, backup wins)**: importing a backup replaces the
  local vault, then — if sync is on — the backup becomes authoritative on the
  server too. Imported entries are flagged `restored`; the next sync rebases
  them onto the server's current revs and pushes, so the backup overwrites
  matching server entries and revives ones it had deleted, while entries that
  exist only on the server are kept (a merge, not a mirror). It never raises
  conflicts. The imported wrapped-key record only seeds an empty server; an
  existing server meta wins (so restoring the same vault won't revert a
  password changed on another device).

## Go server

A single-file Go program that serves the PWA front end and stores the
client-encrypted entries in SQLite — use `modernc.org/sqlite` (pure Go, no
CGo) to keep single-binary cross-compilation and tiny Docker images. By
default the database lives in the same directory as the executable,
configurable with runtime flags.

The server runs wherever the person's needs dictate:

- **Desktop only**: run it on their mac/windows/linux machine; the PWA talks
  to the local server (and can also keep multiple browser brands in sync).
- **Public sync**: run it on a very small public VM (likely in Docker) so
  passwords sync between devices on different networks. This mode requires:
  - a shared-secret auth token — the data is ciphertext, but without auth
    anyone who finds the URL could tamper with or delete it;
  - HTTPS via Let's Encrypt or a reverse proxy such as Caddy (the template's
    mkcert certs are LAN-only).

Once the app is installed as a PWA, having the server running is recommended
but not required — the PWA works fully offline.

## Sync & conflicts

Entries can be added, changed, and deleted while offline, then synced when a
server is reachable. Sync compares per-entry `updatedAt`: non-overlapping
edits merge silently. When the same entry changed on both sides, never guess
— show the user both versions and let them decide. They can defer, but an
unresolved conflict stays highlighted somewhere in the UI until resolved.
Reuse the template's SSE `/events` channel to notify connected clients when
entries change.

## Non-goals

- **Autofill**: impossible for web tech (needs a native app or browser
  extension). Lean into what a PWA does well instead — fast offline access,
  install-to-homescreen, copy buttons with auto-clearing clipboard.
- Keep the vault logic (crypto, storage, sync) in a cleanly separated JS
  module so a desktop browser extension (which gets autofill + offline
  inherently) can be added later without rework.

## Data to Store
The following data will be kept for each password entry
- Title
- username
- password
- url
- general notes
- created timestamp
- last modified timestamp

These fields are the *encrypted payload* — they live inside each entry's
ciphertext as a JSON object (JSON, not fixed columns, so future fields like a
TOTP secret can be added without a schema change). They sit inside the sync
envelope from the data model above: `{id, ciphertext, updatedAt, deleted}`.
The envelope's `updatedAt` is the only timestamp the server can see and is
what sync compares; the payload's own created/last-modified timestamps stay
encrypted.


## UI
The user interface will have a search function. It will be the standard type
that shows all the records, then as you type, the list gets smaller as only
records that match your search are shown.
Whle in search mode, only title, username and url are shown, but the search
will will include the passwork and notes fields in deciding what records
to show.
When the user clicks on a record, a modal appears, showing all the data
for the record.

The username, password and url fields have an icon to copy their contents
to the clipboard. Copying the password wipes the clipboard automatically after
a short delay (~20s). This delay can be changed by the user (Settings).
The url field additionally has an icon to open it in a new browser tab, and new
entries pre-fill the url with `https://` to save typing (a bare scheme is
treated as empty on save).
In the modal the password is masked by default with a reveal (show/hide) toggle.

Supporting flows the above depends on:

- **Unlock / first run**: the whole app sits behind a lock gate. On first run
  the user sets the master password (entered twice); on later launches they
  enter it to unlock. Nothing is shown or decrypted until unlocked.
- **Add / edit / delete**: an add button creates a new entry; the record modal
  has edit and delete actions. Deletes are tombstones (see the data model).
- **Auto-lock**: the vault re-locks after a period of inactivity and via an
  explicit lock button, requiring the master password again.


# Public Use
As the server is zero trust, if you want public sync on your devices, you can
set up your own, or, with their permission, use someone elses.
Various people can share a server, and they don't have to trust one another.
At no point does the server ever see unencrypted data. It's simply a portal
to sync through.
It uses such little resources than many people can share a server on a very
low powered machine.



# PWA Template
## Commands
This repo is a GitHub *template* for PWA apps with a hamburger menu. All
name-specific strings use the placeholder "My App" / `myapp`; the README's
"Using this template" section lists every file to touch when renaming for a
new project — keep that list up to date if you add another.
```sh
go run . -dev                       # development: serves web/ from disk, so edit + refresh (no rebuild)
go run . -dev -db /tmp/vault.db     # dev with an explicit sync DB (dev exe is temp, so pass -db)
go build -o ownvault .              # production: single binary with web/ embedded via go:embed
./ownvault -addr :3000              # default addr is :8080
./ownvault -token "$(openssl rand -hex 16)"   # public deployment: require a shared-secret token
```

`-db` sets the SQLite sync database (default: `ownvault.db` next to the
executable). `-token` (or env `OWNVAULT_TOKEN`) requires that shared secret on
all `/api/*` calls — set it for any public/internet-reachable deployment.

There are no tests or linters configured. `web/` files are embedded at build
time, so changes to them require a rebuild unless running with `-dev`. The Go
sync layer uses the pure-Go `modernc.org/sqlite` driver (no CGo), so
cross-compilation and the single-binary story are preserved.

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
  path (`/settings`, `/about`, ...) returns the shell `web/index.html`. The
  `/api/*` sync endpoints and `/events` are handled before that catch-all.
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
it would hang) and must keep doing so. The service worker also bypasses
`/api/*` — sync must always hit the network, never a stale cache.

**Sync (the Own Vault layer)** — three JS files with a strict separation:

- `web/js/vault.js` owns *all* crypto and IndexedDB. DOM-free, so it can back
  a browser extension later. Each entry envelope is `{id, iv, ciphertext,
  updatedAt, deleted, rev, dirty, conflict, remote}`: `rev` is the last
  server revision seen (the sync base), `dirty` marks unpushed local edits,
  `conflict`/`remote` hold a divergence pending user resolution. It exposes
  sync helpers that speak base64 (`pendingPush`, `applyPulled`, `confirmPushed`,
  meta doc get/set, cursor, `listConflicts`, `resolveConflict`) so the sync
  engine never touches binary or keys.
- `web/js/sync.js` is HTTP-only orchestration: `pull` (since a cursor) then
  `push` (optimistic concurrency), triggered on unlock, on local change
  (debounced), on an SSE `changed` event, or manually. Config in localStorage
  (`syncEnabled`, `syncToken`); URLs are same-origin.
- `web/js/vaultui.js` is all the DOM glue (lock gate, list/search, record
  modal, conflict banner + resolution modal, settings controls).
- `main.go` stores only ciphertext in SQLite, assigns a monotonic `rev` per
  write, and on `/api/push` accepts an entry only if the server's current rev
  still equals the client's `base` (else it returns the server's version as a
  conflict). It broadcasts a `changed` SSE event after any accepted write.
  Zero-knowledge holds: `rev` is the only server-managed metadata.

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
