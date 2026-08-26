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
- Master password → KDF → **wrapping key**, which encrypts only the vault
  key. The KDF is versioned in the record: `v: 2` = Argon2id (64 MiB / 3
  passes / 1 lane, via the vendored WASM module `web/js/argon2.min.js` —
  WebCrypto has no Argon2), used for every new record; `v: 1` = PBKDF2-SHA256
  600k stays decodable forever (old vaults and backups). Because every
  re-wrap goes through `wrapVaultKey`, v1 vaults migrate to Argon2id
  automatically on their next password change or full re-encrypt. If the WASM
  module fails to load, wrapping falls back to v1 and unlock of a v2 record
  reports the module failure (not "wrong password"). The resulting
  **wrapped-key record** (wrapped vault key + salt + KDF params) is one small
  piece of vault metadata — none of it is secret, and it must survive
  export/import and sync alongside the entries.
- Unlock = attempt to unwrap the vault key. A wrong master password is
  detected by AES-GCM authentication failure on that one record — immediate,
  unambiguous, and no separate password hash is stored anywhere.
- Changing the master password = re-wrap the vault key with the new wrapping
  key and atomically replace the wrapped-key record. One tiny write — no mass
  re-encryption of entries, so an interrupted password change can't leave the
  vault half-migrated across two keys.
- Caveat: re-wrapping protects against future guessing of the old password,
  but anyone who already copied the vault *and* knew the old password has the
  vault key forever. So alongside "change password", Settings offers **Full
  re-encrypt** (`vault.js` `reencrypt`) for suspected compromise: fresh vault
  key, every entry re-encrypted under it, wrapped under a *new* master
  password (keeping the compromised one would be defeated by the next stolen
  backup). Interruption safety comes from atomicity, not migration markers:
  all new ciphertexts are computed in memory, then the new wrapped-key record
  and every envelope commit in ONE IndexedDB transaction — a crash leaves the
  vault entirely on the old key. The server's write-auth claim rotates via
  `X-Vault-Write-New` on the meta push (the old credential rides the dirty
  meta record's `rotate` field so a crash between local commit and sync still
  rotates later). Other devices auto-lock when pulled envelopes stop
  decrypting (vaultui `loadEntries`) and re-unlock with the new password.
  Re-encrypt also rebinds any remaining legacy (pre-AAD) ciphertexts.

Hardening rules layered on that design (all in `vault.js` — keep them intact):

- **Entry ciphertexts are id-bound (v2 format)**: a 4-byte `"OV2\0"` magic
  prefix, then AES-GCM output made with the entry id as `additionalData`.
  Every entry shares one vault key, so without AAD a malicious server could
  swap ciphertexts between entries or replay old blobs under any id. Legacy
  unprefixed ciphertexts still decrypt (no AAD) and are rebound on the next
  write of that entry; the magic prefix is what stops the legacy fallback
  being used to defeat the binding on entries known to be bound.
- **The live vault CryptoKey is non-extractable** (`extractable: false`).
  Nothing exports it (change-password and backup use the wrapped record), so
  page script — XSS, a hostile extension — can use it while unlocked but can
  never read the key material.
- **KDF params from the network are bounded** — PBKDF2 iterations 100k–10M,
  Argon2 memory 8 MiB–1 GiB / passes 1–10 / lanes 1–4 — enforced where
  records are ingested (`docToMeta` for synced meta, `importVault` for
  backups) and again in `deriveWrappingKey`. Tampered params can't leak
  anything, but absurd ones would hang or OOM the device (DoS) and the
  floors block quiet downgrades.
- **Master password minimum is 12 characters** (create + change, vaultui.js):
  the vault is offline-brute-forceable from a stolen backup or server DB, so
  the password carries the whole load.

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
  password changed on another device). A v2 backup file also records the
  (non-secret) Vault ID; import adopts it (`Sync.setVaultId`) so the restored
  device reattaches to the same server namespace instead of forking a new one,
  and the rebase above runs against that vault's live state. Restore is
  reachable from the lock gate too ("Restore from a backup file"), so a fresh
  device with no vault can recover before there is anything to unlock.

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

Server hardening (in `main.go` — keep these when touching handlers):

- Every response carries a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`
  — the wasm allowance admits only WebAssembly compilation for the Argon2id
  module, never JS eval; no inline scripts;
  `manifest-src 'self' blob:` for the client-generated manifest) plus
  nosniff / frame-deny / no-referrer; HSTS on the TLS listener only. The app
  must stay CSP-clean: no inline scripts, styles, or `hx-on` attributes.
- Token comparison is constant-time (`crypto/subtle`).
- `/api/meta` and `/api/push` bodies are capped (`http.MaxBytesReader`) so one
  client/tenant can't fill a shared server's disk or RAM.
- `/events` has a global connection cap (it is deliberately unauthenticated).
- When the TLS listener is up, plain HTTP from anything but loopback is
  redirected to HTTPS, so the sync token never travels in the clear
  (`-plainhttp` opts out for setups where the HTTPS port isn't reachable).
- Per-vault write auth (`X-Vault-Write`): the client derives a credential from
  the vault key (`vault.js` `deriveWriteAuth`, SHA-256 over a domain tag + the
  raw key, computed at the only moments the raw bytes exist); the server
  claims it hash-stored on a vault's first write (TOFU, `vault_auth` table)
  and requires it on every write after. So co-tenants on a shared server
  can't overwrite each other's ciphertext, with no extra secret to copy
  between devices — unlocking IS the proof. Reads stay gated by the server
  token + unguessable vault id (a fresh device must pull the wrapped-key
  record before it can unlock). `X-Vault-Write-New` on `/api/meta` PUT
  rotates the credential (used by full re-encrypt, which replaces the vault
  key). Remaining documented trade-off: anyone with the server token and a
  vault id can still *read* that vault's ciphertext and squat an
  as-yet-unclaimed (never-written) vault id.

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
- `critical` flag (boolean) — marks an entry for the printed emergency
  recovery sheet (see UI). Optional; absent/false on entries created before the
  feature.
- `totp` — the site's 2FA setup key as normalized base32 (RFC 6238 TOTP,
  fixed at SHA-1 / 6 digits / 30 s). Optional; empty/absent when the entry has
  no 2FA. `web/js/totp.js` (DOM-free, like vault.js) validates it on save
  (`Totp.normalize`, which also accepts a pasted `otpauth://` URI and rejects
  non-default parameters) and generates the live code in the record modal
  (`Totp.code`, WebCrypto HMAC — no dependency). Excluded from search. See
  DESIGN-DECISIONS.md for the one-factor trade-off.

These fields are the *encrypted payload* — they live inside each entry's
ciphertext as a JSON object (JSON, not fixed columns, so future fields like a
TOTP secret can be added without a schema change — `critical` was added exactly
this way). They sit inside the sync envelope from the data model above:
`{id, ciphertext, updatedAt, deleted}`.
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

If the entry has an authenticator key (`totp` field), the modal shows a live
**Verification code** row: the current 6-digit code, a countdown bar, and a
copy icon (no clipboard wipe — the code self-expires). The 1 s tick derives
everything from `Date.now()` so a suspended background tab shows the right
code immediately on resume, and the interval is killed on modal close, entry
switch, edit, and lock (the closure holds the secret, so it must never
outlive the modal's plaintext). Critical entries print their authenticator
key on the emergency recovery sheet.

**Critical entries + emergency recovery sheet.** The add/edit form has a
"Critical" checkbox (stored as the `critical` payload field); such entries show
a violet badge in the list and record view. Settings → *Emergency recovery
sheet* → "Print recovery sheet…" gathers every critical entry, shows a blunt
warning (plaintext passwords; printers can retain copies; store the paper
securely / shred old ones), then renders a print-only sheet (`#print-sheet`,
revealed by an `@media print` rule while `body.printing-sheet` is set) and calls
`window.print()` — straight to the printer, no PDF. Values are monospace so
seed phrases / backup codes transcribe unambiguously. The plaintext is wiped
from the DOM on `afterprint` and on lock. This is an offline last resort,
immune to device failure / ransomware.

Supporting flows the above depends on:

- **Unlock / first run**: the whole app sits behind a lock gate; nothing is
  shown or decrypted until unlocked. On a fresh device with sync on, the gate
  is a **Connect** step (join an existing vault by its Vault ID + token, or
  start a new one, or restore from a backup file); creating a new vault mints a
  Vault ID and shows it once on a welcome step. On later launches the gate is
  just the unlock prompt. See Public Use for the Vault ID model.
- **Add / edit / delete**: an add button creates a new entry; the record modal
  has edit and delete actions. Deletes are tombstones (see the data model).
  Destructive prompts (delete, restore, print recovery sheet) use the in-app
  themed `confirmDialog()` in vaultui.js, never `window.confirm`.
- **Auto-lock**: the vault re-locks after a period of inactivity and via an
  explicit lock button, requiring the master password again.
- **Vault name (PWA icon name)**: the create screen prompts for a short name
  ("Home", "Work"); it labels the installed app icon and the lock screen. It is
  a **property of the vault, synced end-to-end**: stored as a reserved encrypted
  entry (`vault.js` `SETTINGS_ID = "__vault__"`, payload `{name}`) that rides the
  normal per-entry sync — deliberately NOT the wrapped-key meta doc, whose server
  write is last-writer-wins and could clobber a password change. So a device that
  **connects** to an existing Vault ID *inherits* the name on first unlock (no
  name field on the connect screen), and renaming on any device propagates to all
  of them; the server only ever sees the ciphertext. `vaultui.js`
  `reconcileVaultName()` (run on unlock and after each sync) adopts whatever the
  vault carries — or seeds the vault from a pre-existing local-only name, so
  older/single-device vaults migrate automatically. The name is hidden from the
  list/search/count and never raises a sync conflict (name-vs-name auto-merges
  last-writer-wins in `applyPulled`). Two layers hold it: `vault.js` (the synced
  encrypted copy) and `web/js/app.js` — the shell, which owns the `<link
  rel="manifest">` + `<title>` and keeps a local `localStorage vaultName` mirror
  for use before unlock (the manifest is set on every load). app.js drives the
  installed-app name via a **client-generated manifest** (a `blob:` URL with the
  name baked in) so the name never reaches the server — preserving zero-knowledge
  even on shared/public servers. (There is deliberately no server-side manifest
  naming: it would be the one path leaking the plaintext name to the server.)
  Icon URLs in that manifest must be absolute (a blob URL has no base); its
  `id`/`start_url` stay constant so a rename relabels the *same* app instead of
  installing a duplicate. If a browser rejects a blob manifest, it falls back to
  the static `manifest.webmanifest` (default name) — the user renames the icon
  once. iOS ignores the manifest for naming, so app.js also sets an
  `apple-mobile-web-app-title` meta from the name (the Add-to-Home-Screen sheet
  is user-editable regardless). An already-installed app keeps its old icon name
  until reinstalled.


# Public Use
As the server is zero trust, if you want public sync on your devices, you can
set up your own, or, with their permission, use someone elses.
Various people can share a server, and they don't have to trust one another.
At no point does the server ever see unencrypted data. It's simply a portal
to sync through.
It uses such little resources than many people can share a server on a very
low powered machine.

**Multi-tenancy — the Vault ID.** Sharing works via a per-vault namespace key.
Each vault mints a random **Vault ID** at creation (client-side, kept in
localStorage as `vaultId`); the client sends it as `X-Vault-Id` on every
`/api/*` call, and the server scopes *all* storage by it — `entries` and `meta`
are keyed by `vault_id`, and each vault has its own private `rev` sequence in
the `revs` table. So unrelated people on one server get fully separate vaults
and can't see or enumerate each other's (already encrypted) data; the server
still only ever sees an opaque id + ciphertext. There are deliberately **no
usernames/accounts** — the Vault ID picks the blob, the master password opens
it. `-token`, if set, is a separate server-wide access gate (not per-person).
A fresh device joins an existing vault via the lock-screen **connect** step
(enter the Vault ID + token); Settings shows the current Vault ID to copy over.
SSE `changed` events are scoped per vault (`/events?vault=<id>`); the `/events`
reachability probe in app.js connects unscoped and just rides the keepalives.
The old single-vault schema (entries keyed by id alone, one `meta` row) is
incompatible; `openStore` refuses such a DB with a clear message rather than
migrating.



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

Deployment is a container behind Nginx Proxy Manager (NPM terminates TLS; the
container is plain HTTP — `certs/` must stay out of the image or the internal
TLS listener + redirect would arm). `Dockerfile`, `docker-compose.yaml`, and
the Makefile implement the staging → promote → rollback flow; DEPLOY.md is
the runbook. Staging has its own DB volume and is a separate vault world —
test vaults only.

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
  `push` (optimistic concurrency), triggered on unlock, on a *genuine local
  edit* (debounced), on an SSE `changed` event, or manually. Config in
  localStorage (`syncEnabled`, `syncToken`, `vaultId`); URLs are same-origin.
  Sync is event-driven, NOT a poll — critically, `Vault.onChange` only schedules
  a sync when the change is a real local edit. `vault.js` `notifyChanged(local)`
  passes `true` only from `put`/`remove`/`importVault`; sync-applied refreshes
  (`applyPulled`/`confirmPushed`/`resolveConflict`) pass nothing, so a sync's own
  UI refresh can't re-trigger a sync (that regression caused a ~1/s idle poll).
- `web/js/vaultui.js` is all the DOM glue (lock gate incl. the connect/welcome/
  restore steps, list/search, record modal, conflict banner + resolution modal,
  settings controls, the critical-entry checkbox + emergency recovery sheet).
- `main.go` stores only ciphertext in SQLite, scoped by the client's Vault ID
  (see Public Use), assigns a per-vault monotonic `rev` per write, and on
  `/api/push` accepts an entry only if the server's current rev still equals the
  client's `base` (else it returns the server's version as a conflict). It
  broadcasts a `changed` SSE event (to that vault's subscribers) after any
  accepted write. Zero-knowledge holds: the server-managed metadata is `rev`
  plus the opaque, client-supplied `vault_id`.

## Conventions

- There are two colour schemes, picked on the Settings screen and persisted
  in localStorage: "midnight" (`#0a1f3b`, the default) and "classic"
  (`#1a4080` bar + accent hamburger). The scheme colors live in `:root` /
  `body.theme-classic` in `web/css/style.css` and again in the `SCHEMES` map
  in `web/js/app.js` (which drives the `<meta name="theme-color">`); both
  must stay in step, and `web/manifest.webmanifest` `theme_color` must match
  the midnight default.
- The app icon is a gold padlock (evoking the 🔐 lock-gate logo) on the
  midnight background. `web/icons/lock.svg` is the source of truth: a
  transparent-background version wired as the SVG favicon
  (`<link rel="icon" type="image/svg+xml">`) and as an `any`-purpose manifest
  icon. `web/icons/lock-maskable.svg` is the same lock on an opaque midnight
  fill inside the ~66% maskable safe zone; the PNGs in `web/icons/`
  (`icon-192`, `icon-512`, `apple-touch-icon` at 180px, flattened opaque) are
  rasterised from it — no SVG rasteriser is installed, so render via
  `qlmanage -t -s 1024` (bump the SVG's `width`/`height` to 1024 first so it
  fills the square) then downscale with `sips`. `assets/logo.png` is an older
  unused source asset, not served.
- When a screen later needs live data, replace its static fragment with a Go
  handler that renders the same fragment HTML; the htmx side doesn't change.
- JS is written in ES5 style (`var`, function expressions) — match it.
