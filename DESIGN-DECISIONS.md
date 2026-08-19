# Design decisions

Non-obvious choices and the reasoning behind them, for reviewers (human and
Claude). The big architectural picture lives in CLAUDE.md; this file records
the "we could have done X, we chose Y because…" calls. Newest at the top.

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

### No rate limiting on the server token either — a real gap, not a decision
`auth()` (`main.go`) does a constant-time compare and returns 401. Nothing
counts failures, so `/api/*` can be hammered at line rate indefinitely. The
only limiters on the server are the `/events` connection cap and the
`MaxBytesReader` body caps.

Why this hasn't bitten: the README's `openssl rand -hex 16` gives a 128-bit
token, and `vaultId` is 128 bits from `getRandomValues` — both unguessable at
any request rate. But nothing *enforces* that: `-token hunter2` is accepted
silently, and then unlimited online guessing is a live attack. On a
token-less server (the LAN/desktop default) the vault ID is the sole barrier,
again with unlimited attempts — safe only by entropy, with no depth behind it.

Deferred, not dismissed (TODO.md). The fix that matches this codebase is a
per-IP failure counter in front of `auth()` — a small mutex-guarded map,
lazily cleaned, 429 after N failures — no dependency. It won't stop a
distributed attacker; it turns "unlimited online guessing" into "you need a
botnet", which is the honest bar for a self-hosted single binary. A minimum
length/entropy check on `-token` at startup is the cheaper half of the same
fix and should land with it.

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
