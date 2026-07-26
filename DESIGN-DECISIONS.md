# Design decisions

Non-obvious choices and the reasoning behind them, for reviewers (human and
Claude). The big architectural picture lives in CLAUDE.md; this file records
the "we could have done X, we chose Y because…" calls. Newest at the top.

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
