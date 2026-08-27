# Design decisions

Non-obvious choices and the reasoning behind them, for reviewers (human and
Claude). The big architectural picture lives in CLAUDE.md; this file records
the "we could have done X, we chose Y because…" calls. Newest at the top.

## The website is a separate module, and has no JavaScript (2026-08)

`site/` holds the public website: a landing page and a contact form. Three
calls in it are worth recording.

**Its own `go.mod`, not a package of the vault server.** The obvious layout is
`go build ./site` in the existing module. That was rejected because the site
needs `github.com/hammondus/mailer`, and the vault server has no business
carrying an SMTP client. A nested `go.mod` removes `site/` from the parent
module automatically, so `go build ./...` and `go vet ./...` at the root never
see it and the dependency trees stay disjoint. The cost is remembering to run
`make` from `site/`, which the README says in its second line.

The same split applies to deployment: the site gets its own `Dockerfile` and
`docker-compose.yaml`, and a copy edit never restarts a container people are
syncing vaults through.

**No JavaScript at all.** The contact form is a plain HTML POST. That is not
minimalism for its own sake — it is what lets the CSP be `script-src 'none'`,
under which an injected `<script>` has nothing to run in. Client-side
validation would have bought a slightly nicer error experience in exchange for
the strongest header on the page.

**Anti-spam without a CAPTCHA.** A CAPTCHA means a third-party script, which
the paragraph above rules out, and it taxes every visitor to stop a robot.
Instead: an off-screen honeypot field (off-screen rather than `display: none`,
because some bots skip fields that are not rendered), an HMAC-signed timestamp
in each rendered form that rejects submissions faster than three seconds or
older than two hours, three submissions per IP per hour, and a 64 KiB body cap.
The HMAC key is generated per process — a restart invalidating open forms is a
fair trade for keeping a secret out of configuration.

The form's `From` is always our own verified address and the visitor's address
goes in `Reply-To`. Sending as an address on someone else's domain fails SPF
and burns the sending domain's reputation.

**Asset hashes are per file, not one version for the site.** The first cut
hashed `style.css` and stamped that one version onto every asset URL. That is
wrong in a way that only shows up later: an edited image whose URL did not
change stays cached for a year. `hashAssets` walks `web/` at startup and
records a hash per path. Hashing once at startup is correct only because the
files are embedded and cannot change under a running process — in `-dev` they
are read from disk, so hashing is skipped and `no-cache` does the work.

**The screenshots are generated, not curated.** `site/tools/shots.js` drives a
real browser against a real vault, seeded with invented logins, and writes
`web/img/*.png`. Checking the tool in rather than only its output means a UI
change is one `make shots` away from accurate marketing, instead of five stale
PNGs nobody dares touch. Playwright is installed on demand by that target and
is never a dependency of the site, which still ships no `node_modules`.

## Why there is a server token at all (2026-08)

The vault is client-encrypted, so the token is easy to mistake for a
redundant layer. It isn't — but it also isn't what keeps secrets secret.
The master password owns **secrecy**; the token owns **availability and
abuse**. Without it, anyone who finds the server's URL could:

1. **Store junk.** Mint unlimited vault ids and fill the disk. The
   per-request body cap limits one request, not a loop — a tokenless server
   is a free anonymous dead-drop.
2. **Read ciphertext whenever a Vault ID leaks.** The id is unguessable but
   travels in places the master password never does (the SSE URL
   `?vault=<id>` can land in proxy logs). Ciphertext in hand means unlimited
   *offline* brute force against the master password — the exact attack the
   12-character minimum and Argon2id exist to slow. The token makes a leaked
   id alone worthless.
3. **Squat unclaimed vaults.** Per-vault write auth protects claimed vaults
   even from token holders, but it's TOFU — first write wins. Tokenless, an
   attacker could claim a Vault ID before its owner's first sync.

Because the token is an anti-abuse gate and not part of the encryption, it
can be server-wide and shared between co-tenants without weakening anyone's
vault — and it's optional for localhost/LAN setups, where "found the URL"
isn't a meaningful attacker. This is also why bundling it into the setup
code (next entry) costs nothing: it was never the secrecy boundary.

## Setup code: one paste to connect, QR rendered server-side (2026-08)

Connecting a new device needed two long pastes (Vault ID, then token). The
setup code bundles them: `ov1.` + base64url(vaultId) + `.` +
base64url(token) + `.` + base64url(origin), composed client-side in sync.js.
The connect screen's ID field accepts either form. Design points:

- **Parts are base64url-encoded** because the token is admin-chosen and
  could contain the separator. The origin part rejects a code pasted into a
  different server's app, and gives the (non-same-origin) browser extension
  the server URL when it grows setup-code support.
- **No security change**: both values already travel together through the
  same channel during setup, and the code grants exactly what ID+token
  grant — ciphertext read. The master password is deliberately absent.
- **The QR is rendered by the server** (`/api/setupqr`, `rsc.io/qr` — the
  same dependency teenyurl trusts). This looks like a zero-knowledge
  violation but isn't: every value in the code is already server-known (the
  vault id rides every API call, the token is the server's own, the URL is
  its address). The alternative was vendoring a JS QR encoder; a
  ~zero-dep Go library the reviewer already knows beat ~50 KB of vendored
  JS. Rendering needs the server up, which is fine — connecting a new
  device needs the server up anyway.
- **POST, not GET, and `no-store, private`**: the code contains the token;
  query strings land in access logs and caches. The client fetches the PNG
  with auth headers and shows it via a blob object URL (a plain `<img src>`
  can't send headers), which is why CSP `img-src` gained `blob:`. The QR is
  rendered on demand and torn down on toggle, fragment swap, and lock.
- **The QR encodes the setup *link*** (`https://server/#ov1...`), and the
  connect screen has an **in-page scanner** (vendored jsQR, Apache-2.0,
  loaded on first use — Safari has no BarcodeDetector). The scanner is the
  primary flow: the OS camera app treats plain text as a search query, and
  on iOS a scanned link opens Safari — a different storage container than
  the installed app, so it bootstraps the wrong copy. The link form exists
  so the bare-camera path still lands somewhere useful: the app prefills
  the connect field from the fragment (never auto-connects — page loads
  shouldn't have side effects) and strips it with `replaceState` in every
  gate mode, so the token doesn't linger in the address bar or history
  entry. A magic link as the *only* mechanism was rejected for exactly that
  history exposure; as a fallback behind the scanner, with stripping, the
  trade is worth it.

## Settings: token is retrievable; "remove from device" instead of uninstall (2026-08)

Two related Settings calls:

- **The access token has Show and Copy buttons.** It was masked with no way
  back — but connecting a new device needs Vault ID *and* token, and Settings
  only surfaced half. Masking the token is shoulder-surfing hygiene, not
  secrecy: it lives in plaintext localStorage (see the credential-storage
  entry below), and Settings is only reachable unlocked, where real passwords
  sit behind the same reveal pattern. Copying it does NOT auto-wipe the
  clipboard (unlike passwords): the whole point is pasting it on another
  device, often via a cross-device clipboard minutes later.
- **"Remove vault from this device" wipes; it cannot uninstall.** There is no
  web API for a page to uninstall a PWA — install has one, uninstall is
  browser chrome only. The wipe deletes what actually matters and what an
  icon-uninstall can leave behind (on desktop Chrome, site data survives
  uninstall unless a checkbox is ticked): the IndexedDB vault, all
  localStorage, the service worker, and caches — then reloads into the
  first-run gate. `localStorage.clear()` over selective key removal, on
  purpose: decommissioning wants first-run state, and a curated key list
  would silently rot as keys are added. The confirm dialog owns the two
  blunt truths: unsynced changes are gone for good, and the icon must be
  removed by hand.

## Create gate probes server auth; only a 401 blocks (2026-08)

Creating a vault on a token-protected server used to succeed locally and
then fail every push with a silent 401 — the create path never asked for the
token (only connect did), and the only symptom was a status line in
Settings. Found in the first real deployment: the first sign of trouble was
the *second* device failing to connect to a vault the server had never seen.

"Start a new vault instead" now probes `/api/state` (the purpose-built
reachability/auth endpoint) with whatever token was typed, and refuses to
advance to the create form unless the server answered and accepted the
token. Choices within that:

- **No token field on the create form**: the create form is also the offline
  and no-token-server path; a field that is usually irrelevant invites
  confusion, and the connect screen already has the field — the gate just
  has to enforce it.
- **An unreachable server blocks too, with a message pointing at "Use
  offline only".** First instinct was to let it pass (offline-first), but
  offline-first doesn't apply to initial setup: a fresh device loaded this
  very page from the server, so the server was reachable moments ago. The
  only offline route to the connect screen is a previously cached shell, and
  a user genuinely creating offline has the explicit offline button — which
  disables sync, so nothing 401s silently later. Blocking both outcomes
  means a *synced* vault can only ever be created after the server
  affirmatively accepted the token; there is no residual silent-401 gap.

## Extension: offscreen document as the vault process (2026-08)

The Chrome MV3 extension reuses vault.js/totp.js/sync.js unmodified (the
payoff of keeping them DOM-free), assembled by `make extension` into
`dist/extension/` — a build-time copy, not checked-in duplicates, so web/js
remains the single source of truth. Decisions:

- **The unlocked key lives in an offscreen document, not the service
  worker.** MV3 service workers are evicted after ~30 s idle; the unlocked
  vault key is a non-extractable CryptoKey that cannot be serialized into
  chrome.storage (by design — non-extractability is the point). An offscreen
  document persists for the browser session, runs real DOM/WebCrypto, and
  gives IndexedDB + localStorage the same shape the PWA code expects. The
  service worker's only job is creating it.
- **Chrome-first.** Firefox's MV3 has no offscreen API (its event pages
  would host the vault instead); supporting it is a different lifetime
  model, deferred until wanted.
- **v1 is read + fill + copy.** Editing, restore, create, conflict
  resolution stay in the PWA. Cuts the popup to a fraction of vaultui.js
  and keeps the extension's write path (and its attack surface) at zero.
- **Fill is explicit, not inline.** No injected dropdowns in page forms —
  the user picks an entry in the popup and clicks Fill (or copies). Inline
  UI is where autofill spoofing bugs live; explicit fill still removes the
  clipboard from the common path. The content script is passive: no state,
  no reading the page, acts only on the popup's message to the active tab.
- **Site matching is suffix-only and one-directional**: the entry's host
  must equal, or be a parent domain of, the tab's host. An entry saved for
  example.com offers itself on login.example.com; an entry for
  app.example.com never offers itself elsewhere.
- **Secrets move per entry, on demand.** The popup list carries metadata
  only; ov:credentials fetches one entry's password when viewed/filled, and
  the TOTP code is computed in the offscreen document so the TOTP *secret*
  never leaves it.
- **Clipboard wipe lives in the offscreen document** (execCommand on a
  focused textarea — the documented offscreen clipboard path): the popup
  closes on focus loss, so a popup-owned timer would never fire.

## Deploy: primed's staging/promote pattern, with per-instance DBs (2026-08)

The Docker deploy copies `~/dev/_live/primed`'s shape: the compose file only
runs images tagged `ownvault:<git-sha>` (never builds), staging is behind a
compose profile, `make promote` points production at the exact image staging
proved, and `make rollback TAG=` is a container swap. The reasons are
primed's and aren't restated here (see its docker-compose.yaml header).

What's different, and why:

- **Each instance owns a writable SQLite volume; they never share.** Primed's
  instances share one read-only mmap'd index — the cheap case. Here the state
  is a live database: sharing would mean lock contention between two servers
  and a staging bug corrupting real vaults. Staging starts empty and holds
  test vaults only. The browser reinforces the split for free: hostname =
  origin = its own IndexedDB / service worker / PWA install.
- **TLS stays out of the container entirely.** The server grows a TLS
  listener (plus a plain-HTTP→HTTPS redirect) whenever `certs/` exists, which
  is a LAN-dev convenience; behind NPM it would break every proxied request.
  `.dockerignore` excludes `certs/`, making the container structurally unable
  to enter that mode — no `-plainhttp` flag needed. HSTS is enabled in NPM,
  since the app only sends it from its own TLS listener.
- **SSE through nginx**: `/events` sets `X-Accel-Buffering: no` so nginx
  streams events instead of buffering them (buffered SSE = laggy sync and a
  lying reachability indicator). The 25 s keepalive already sits under
  nginx's default 60 s `proxy_read_timeout`.
- **Separate staging token** (`OWNVAULT_STAGING_TOKEN`, falling back to the
  production token): a token pasted into test devices shouldn't be a
  production credential. The tokens are server-wide gates, not per-vault
  secrets, so nothing else distinguishes the instances.
- **No smoke endpoint was added**: `make smoke` GETs `/`, which serves the
  app shell and proves NPM → container → server end to end. A `/api/health`
  would tell an unauthenticated caller the service exists in more detail than
  a password server needs to volunteer.

## TOTP codes in the vault: one factor, on purpose (2026-08)

Entries can hold the site's 2FA setup key (`totp` payload field); the record
modal renders the live 6-digit code. Storing TOTP secrets beside passwords
collapses two factors into one — whoever opens the vault gets both. That's
the standard criticism of Bitwarden's identical feature, and it's accepted
here for the same reason: the second factor's real-world value is mostly
against *password* compromise (phishing, reuse, the site's own breach) —
threats where the vault isn't the thing stolen. Against vault compromise it
was already game over. Per-entry opt-in leaves the choice with the user;
2FA for the highest-stakes accounts can stay on a separate device by not
entering it here.

Choices inside that:

- **Fixed parameters** (SHA-1 / 6 digits / 30 s): authenticator apps assume
  them and mostly ignore `otpauth://` parameters claiming otherwise. An URI
  declaring different parameters is rejected at save rather than stored and
  silently wrong. (Same stance as `hammondus/mfa`, which was the test oracle
  for `totp.js` — RFC 6238 Appendix B vectors, including a >32-bit step to
  exercise the 64-bit counter, since JS bitwise ops truncate at 32.)
- **Generation is client JS, not the Go module**: codes must render offline
  in the browser; TOTP is ~40 lines over WebCrypto HMAC-SHA1. `totp.js` is a
  separate DOM-free module (not vault.js) so the future extension can import
  it, and it omits the server-side halves (replay tracking, recovery codes) —
  a generator has no replay to prevent.
- **QR scanning reuses the connect scanner** (2026-08; originally rejected as
  "camera plus a QR-decode library fails the dependency test"). The setup-code
  work later vendored jsQR and built the camera overlay anyway, so the
  marginal cost of a scan button on the edit form dropped to a callback:
  `startScan` takes a per-caller `{hint, onCode, onError}` and the 2FA caller
  accepts only `otpauth:` payloads (any other QR is ignored and scanning
  continues; an otpauth URI that `Totp.normalize` rejects stops the scan and
  surfaces the error — the user aimed at the right code, so silence would
  read as a broken scanner). Every enrolment screen still shows the key as
  text, so typing it remains the camera-less fallback.
- **Copying a code skips the clipboard wipe** the password copy gets: it
  expires on its own within 30 s, and wiping mid-login is pure annoyance.
- **Recovery codes live in the vault too** (2026-08, `recovery` payload
  field): the same one-factor reasoning covers them — for an entry that
  already stores its TOTP secret they add nothing to an attacker's position,
  and for most users the alternative is a plaintext `recovery-codes.txt` in
  Downloads. The availability question ("codes recover you when the
  authenticator is lost — what if the vault is the authenticator?") is
  answered by the emergency recovery sheet: critical entries print their
  codes, used ones marked. Format is `[{code, used}]`, not free text, so
  tick-off state is structured and survives edits (matched by exact code
  string, so re-pasting or pruning the list never resets ticks). Excluded
  from search like the TOTP key; per-code copy takes the password-style
  clipboard wipe because — unlike a TOTP code — a recovery code stays valid
  until used.
- **Search excludes the key**: matching against base32 noise only produces
  false hits.
- **Caveat**: codes come from the device clock; drift past ~30–60 s produces
  codes the site rejects, and the app can't detect that offline.

## Argon2id via a vendored WASM module (2026-08)

WebCrypto has no Argon2, and a memory-hard KDF hand-rolled in JS would be
both slower (fewer passes affordable in the same unlock latency) and riskier
(fresh crypto code) than the reference implementation. So this is the one
place the no-dependency rule bends, with provenance pinned:

- **Vendored file**: `web/js/argon2.min.js` — the `argon2-bundled.min.js`
  build from **argon2-browser 1.18.0** (MIT, license alongside as
  `argon2.LICENSE`; the Emscripten-compiled Argon2 reference C, WASM inlined
  as base64 so it's a single file with no loader path issues).
- **SHA-256 of the vendored file**:
  `77c64b946baf1a5116dc591f4b9965d636b1b455f75edd2d4a587cb75e01687b`
- **SHA-256 of the npm tarball it came from**
  (`https://registry.npmjs.org/argon2-browser/-/argon2-browser-1.18.0.tgz`):
  `cdb11795a4971bde095fe6b836aa424de50c4558ed4b9505bc74111eee7f6d35`
- The file contains no `eval(`; the CSP gains `'wasm-unsafe-eval'`, which
  admits only WebAssembly compilation — the JS string-to-code paths stay
  blocked.

Parameters: 64 MiB / 3 passes / 1 lane — above the OWASP minimums, ~0.5–2s
per unlock. Ingestion bounds (8 MiB–1 GiB, ≤10 passes, ≤4 lanes) mirror the
PBKDF2 iteration bounds: hostile params can't leak anything, but unbounded
ones are a hang/OOM DoS.

Fallback policy: if the module didn't load, `wrapVaultKey` falls back to a
v1 PBKDF2 record rather than bricking vault creation, and unlocking a v2
record reports the module failure explicitly (an `err.fatal` rejection)
instead of the misleading "incorrect master password".

## Full re-encrypt: atomicity instead of migration markers (2026-08)

CLAUDE.md originally sketched interruption safety for full re-encrypt as
"keep both wrapped keys until every entry carries the new key's generation
marker". The implementation does something simpler and strictly safer
locally: compute every new ciphertext in memory first, then commit the new
wrapped-key record and all envelopes in **one IndexedDB transaction**. There
is no observable half-migrated state — a crash at any point leaves the vault
entirely on the old key, and no marker bookkeeping can drift.

Why this works here and not in general: vault entries are small (a few KB
each) and vaults are thousands of entries at most, so "the whole vault in
memory twice" is megabytes. The marker design earns its complexity only when
the data can't fit in memory or the store lacks multi-key atomic commits;
IndexedDB has them. WebCrypto calls can't run inside an IDB transaction
(any await ends it), which forces the encrypt-first-then-commit shape anyway.

Two deliberate policies around it:

- **A new master password is required**, not optional. The threat this flow
  answers is "attacker has a copy of the vault AND the old password"; a
  re-encrypt that kept the compromised password would be undone by the next
  stolen backup.
- **Unresolved sync conflicts block it.** A conflict's stashed server version
  is old-key ciphertext; re-encrypting around it would leave the "keep
  server" resolution path undecryptable.

Cross-device: the re-encrypted envelopes are ordinary dirty edits (their
`rev` stays the sync base), so they push through normal OCC. Other devices
pull them, fail to decrypt with the in-memory old key, and vaultui locks with
an explanation once a session that HAS decrypted rows sees zero decryptable
rows while envelopes exist (`hadEntries` guard, so a fresh session full of
foreign data never lock-loops). The server's write-auth claim rotates in the
same meta PUT that installs the new wrapped key (`rotate` field on the dirty
meta record survives a crash between local commit and sync).

## Per-vault write auth: derived, not minted (2026-08)

The per-vault write credential (`X-Vault-Write`) is **derived from the vault
key** — `SHA-256("ownvault-write-v1" || raw vault key)` — instead of being a
separate random secret. Three designs were weighed:

- **A minted secret stored in the encrypted `__vault__` settings entry** would
  sync to other devices, but has a bootstrap race: two legacy devices
  generating a key concurrently produce different values, the server's TOFU
  claim takes one, and the loser needs a special "adopt the server's key"
  path that fights the settings entry's last-writer-wins merge.
- **A minted secret the user copies between devices** (like the Vault ID)
  works but adds a second thing to transcribe, and a device that restores
  from a backup wouldn't have it.
- **Deriving from the vault key** has none of that: every device that can
  unlock the vault computes the *same* value (no races, no copying, backups
  included), it survives a master-password change (the vault key doesn't
  change), and the one operation that does replace the vault key — full
  re-encrypt — is exactly where rotation belongs, done via
  `X-Vault-Write-New` on the meta PUT that installs the new wrapped key.

The derivation is one-way (SHA-256), so the credential reveals nothing about
the key; the server stores only a hash of it, so a leaked server DB hands out
no write credentials. It is computed in `create`/`unlock`, the only moments
the raw key bytes exist (the live CryptoKey is non-extractable), held in
memory, and cleared on lock — sync skips the push half while locked and
retries after the next unlock.

TOFU caveat, accepted and documented: an attacker holding the server token
and a vault id could claim a vault that has *never been written*. Real vaults
are claimed by their own first sync, and vault ids are unguessable 128-bit
values, so the window is the moments between minting an id and the first
push.

## Credential storage and guess-rate limiting (2026-08)

### The sync token lives in `localStorage`, deliberately
`syncToken` (the shared server secret, sent as `X-Vault-Token`) and `vaultId`
sit in `localStorage` (`sync.js`). There is no session token anywhere: the
server issues nothing, and nothing expires. The usual "never put secrets in
localStorage" advice targets XSS exfiltration, and the reasoning for keeping
it here is that **the token is not a decryption key** — it gates *write*
access to ciphertext on a zero-knowledge server. Whoever steals it can
vandalise blobs, never read a password. The master password and the vault key
are the things that matter, and neither is persisted: the vault key exists
only as a non-extractable in-memory `CryptoKey` that dies on lock or reload.

Alternatives rejected: `sessionStorage` (dies on every cold launch — an
installed PWA would demand the token on each start, offline included);
`HttpOnly` cookie (unreadable by the `fetch()` code that must set the header,
and it would be attached to navigations the app doesn't control). The
compensating control is the strict CSP — `script-src 'self'`, no inline, no
eval — which is what makes an injection vector expensive in the first place.

Known, accepted on-device leak: `vaultName` is plaintext in `localStorage`
(`app.js`) by necessity, since the shell names the PWA icon and lock screen
before any unlock can happen.

### No rate limiting on the master-password unlock — on purpose
`handleUnlock` (`vaultui.js`) has no attempt counter, lockout, or backoff. A
UI-level limit would be theatre: the vault is offline-brute-forceable from a
stolen IndexedDB or backup file, so an attacker with the device attacks the
wrapped-key record directly at GPU speed and never touches the form. The
defenses that apply to *both* the online and offline attack are the ones
chosen instead — PBKDF2-SHA256 at 600k iterations and the 12-character master
password minimum. Adding a lockout would cost usability and buy nothing
against the threat that actually exists.

### Server token guessing: per-IP failure limiter + token length floor
`auth()` (`main.go`) sits behind a per-IP failure counter (`failLimiter`):
more than 10 failed token attempts in 15 minutes gets 429 until the window
rolls over. Three properties matter more than the numbers:

- **The 429 is issued *before* the compare.** If an over-limit request were
  still evaluated, a wrong guess (429) and a right guess (200) would look
  different, and the limiter would slow nothing. The cost is that a
  legitimate user on a blocked IP also waits out the window — accepted,
  since a success clears the counter and the PWA works offline meanwhile.
- **The bucketing IP is unspoofable in both deployments.** A public
  `RemoteAddr` is used as-is and `X-Forwarded-For` is ignored (anyone can
  send that header). A loopback/private `RemoteAddr` — the reverse-proxy
  deployment, where RemoteAddr would put every client in one bucket — uses
  the *rightmost* XFF value: the one appended by your own proxy, not the
  attacker-supplied left-hand values.
- **The map is capped** (4096 IPs, lazy sweep then arbitrary eviction), so a
  botnet cycling source addresses costs counters, not server memory.

This turns "unlimited online guessing" into ~1k guesses/day per IP. A
distributed attacker isn't stopped — that's the honest bar for a self-hosted
single binary; the token's entropy is the real defence. Which is why the
other half landed with it: `-token` shorter than 16 characters is a startup
fatal (a warning in a Docker log is never read), pointing at the README's
`openssl rand -hex 16`.

Still true on a token-less server (the LAN/desktop default): the 128-bit
vault ID is the sole barrier, with unlimited attempts — a guess returns an
empty vault, not a 401, so there is no failure signal to limit. Safe by
entropy alone; the ID is minted by `getRandomValues`, never user-chosen.

## Post-security-review fixes (2026-07)

### Sync must survive a hostile/corrupt server meta doc
`docToMeta` throws on an out-of-bounds KDF iteration count (deliberate — it's
an ingestion guard). But `sync.js pull()` runs `applyMeta` before applying
entries, so an unhandled throw turned "reject this record" into "abort all
syncing, forever" — a co-tenant with the shared write token could wedge a
victim's sync. Decision: the guard stays in `docToMeta` (single copy of the
invariant; `importVault` builds its record via `docToMeta` too, rather than
hand-copying the check), and `pull()` catches and logs a meta failure, then
carries on pulling entries. The good local wrapped-key record still unlocks
the vault, and a later legitimate meta write (higher rev) is picked up
normally.

### Push is chunked client-side (~2MB batches) under the server's 8MB cap
The 8MB `/api/push` body cap protects a shared server's RAM/disk, but a
backup restore marks every entry dirty at once and the client used to send
them in one POST — a vault over the cap could never sync again (every retry
resent the same oversized body). Decision: keep the server cap, split pushes
client-side. Each batch is confirmed (revs recorded, dirty cleared) before
the next is sent, so an interruption just leaves the remainder dirty for the
next sync — no new failure mode.

### SSE clients rebuild their EventSource after a fatal close
The `/events` endpoint returns 503 at its 256-connection cap (it is
deliberately unauthenticated, so a cap is needed). Per the SSE spec, any
non-200 response "fails the connection": the browser sets the EventSource to
CLOSED and never retries — only *dropped* connections auto-reconnect.
Decision: fix on the client, not the server. Both EventSources (app.js
reachability probe, sync.js change subscription) rebuild themselves with
5s→60s exponential backoff when they observe CLOSED. Alternative rejected:
holding cap-excess connections open server-side and dropping them, which
would trigger auto-reconnect but ties up handler goroutines — the point of
the cap.

### Edit-form password field is `type="text"` + CSS masking
Browser save-password/autofill heuristics key on `type="password"`. A real
password input in the entry edit form makes Chrome/Safari offer to save the
vault entry's plaintext password into the *browser's* (cloud-synced)
password store — the opposite of the app's purpose. Decision: mask with
`-webkit-text-security: disc` on a `type="text"` input (the same technique
the view modal already uses for `.field-value.masked`), which is invisible
to credential heuristics. Fallback behavior in a browser without that CSS
property is an unmasked field — equivalent to the pre-hardening UI, and all
evergreen browsers (Firefox since 132) support it.

### HTTP→HTTPS redirect: loopback exempt by range, `-plainhttp` escape hatch
When the mkcert TLS listener is up, plain HTTP is redirected to it so the
sync token never travels in the clear. Loopback is exempt via
`net.ParseIP().IsLoopback()` (the whole 127.0.0.0/8 + ::1, not just literal
`127.0.0.1` — 127.0.0.x addresses are common for parallel local dev
services). The redirect can strand clients when the HTTPS port isn't
reachable (Docker publishing only the HTTP port, firewalls) — `-plainhttp`
opts out rather than trying to auto-detect reachability.

### HSTS honours `X-Forwarded-Proto`
The documented public deployment terminates TLS at a reverse proxy (nginx
proxy manager / Caddy), where `r.TLS == nil` — the old `r.TLS != nil` gate
meant HSTS was never sent exactly where it mattered. Trusting the header is
safe *for HSTS specifically*: browsers ignore Strict-Transport-Security
received over an insecure connection, so spoofing it on plain HTTP is a
no-op.

### v2 id-bound ciphertext ships with no legacy-write grace period
Entries written by the new code use the "OV2\0" + AAD=id format, which
pre-v2 code cannot decrypt. In a deployed fleet this would need a rollout
grace period (new code keeps *writing* legacy format until all devices have
updated). Decision: skip that machinery — the app is pre-release with no
deployed devices, so version skew across devices cannot occur. Legacy
*reads* still work (unprefixed blobs decrypt without AAD and are rebound on
next write), so existing dev vaults are unaffected. If this ever matters
post-release, the fix is a transitional writer flag, not a format change.
