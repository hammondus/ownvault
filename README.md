# Own Vault

A password manager you actually own. One master password unlocks a database of
logins that is **encrypted in your browser** and only ever leaves it as
ciphertext. The app is a PWA (install it to your phone or desktop, works fully
offline); an optional single-binary Go server syncs it between your devices
without ever being able to read it.

- **Zero-knowledge.** All encryption/decryption happens client-side via
  WebCrypto. The server stores and relays ciphertext and nothing else — no
  plaintext, no keys, no master password.
- **Offline-first.** Entries live in the browser's IndexedDB. You can add,
  edit, and search with no network; sync catches up when a server is reachable.
- **Yours to host.** Run the server on your own machine, on a tiny VM, or use
  someone else's — because it can't read your data, you don't have to trust it.

> Architecture and design rules (crypto layering, data model, conventions) live
> in [`CLAUDE.md`](CLAUDE.md). This README is the operational guide.

## How the crypto works (the short version)

- A random **vault key** (AES-GCM) encrypts every entry individually.
- Your **master password** → Argon2id (64 MiB, memory-hard, so GPU farms lose
  most of their edge; older vaults use PBKDF2 at 600k iterations until their
  next password change) → a **wrapping key** that
  encrypts *only* the vault key. That wrapped-key record is the sole unlock
  artifact — a wrong password simply fails to decrypt it. No password hash is
  stored anywhere, and there is **no recovery**: lose the master password and
  the data is gone.
- Each entry is its own encrypted record `{id, ciphertext, updatedAt, deleted}`.
  The server sees how many entries exist and when they changed — never their
  contents.

## Run it

```sh
go run . -dev                      # development: serves web/ from disk (edit + refresh, no rebuild)
go run . -dev -db /tmp/vault.db    # dev with an explicit sync DB (the dev exe is temp, so pass -db)

go build -o ownvault .             # production: single binary, web/ embedded
./ownvault                         # serve on :8080, DB at ownvault.db next to the binary
./ownvault -addr :3000             # different port
./ownvault -token "$(openssl rand -hex 16)"   # public deployment: require a shared secret
```

Flags: `-addr` (HTTP, default `:8080`), `-db` (SQLite path, default
`ownvault.db` beside the executable), `-token` or env `OWNVAULT_TOKEN` (require
a shared secret on all `/api/*` calls), `-tlsaddr` (HTTPS, default `:8443`, used
when cert/key exist), `-cert`/`-key`, `-healthcheck` (probe a running server's
`/healthz` and exit — the container HEALTHCHECK runs the binary this way,
because the distroless image has no shell).

The SQLite driver is the pure-Go `modernc.org/sqlite` (no CGo), so the single
binary cross-compiles and Docker images stay tiny. There is no build step for
the front end and no `node_modules`.

## Where to run the server

- **Local / desktop.** Run it on your own mac/Windows/Linux box. Your browsers
  (and multiple browser brands) sync through `localhost` or your LAN IP. No
  token needed on a trusted network.
- **Public sync.** Run it on a small VM (typically in Docker) so devices on
  different networks sync. This mode needs two things:
  - **a token** — the data is ciphertext, but without auth anyone who finds
    the URL could tamper with or delete it. Prefer the `OWNVAULT_TOKEN`
    environment variable over the `-token` flag on shared machines (a flag is
    visible to every local user in `ps` output);
  - **HTTPS** — via Let's Encrypt or a reverse proxy such as Caddy. (The mkcert
    certs below are LAN-only.)

  When the built-in TLS listener is active, plain-HTTP requests from anywhere
  but localhost are redirected to it, so the token and ciphertext never travel
  unencrypted. If that redirect would strand clients (the HTTPS port isn't
  reachable, or a reverse proxy terminates TLS in front), opt out with
  `-plainhttp`.

Once installed as a PWA the server is recommended but not required — the app
works fully offline and just syncs when the server is reachable.

## Multiple vaults on one server (and sharing a server)

Every vault has a random **Vault ID** — an opaque namespace key the client
generates when the vault is created and sends on every sync call. The server
keys all storage by it, so **many unrelated people can share one server**, each
with a completely separate vault, and none of them can see (or even enumerate)
another's data. The server still only ever sees an opaque id plus ciphertext.

Because it's zero-knowledge there are **no accounts and no usernames** — the
Vault ID says *which* encrypted blob, and your master password is the only thing
that can open it. The `-token` (if set) is a separate, server-wide "may you
touch this server at all" gate; it is not per-person.

A shared server costs almost nothing per vault, so a handful of friends can run
one tiny box between them without trusting each other with anything.

One honest caveat: sharing a server means trusting the others with
**availability**, not secrecy. Everyone holding the server's token can write to
the server, so a malicious co-tenant could overwrite or delete another vault's
(still unreadable) ciphertext. Your own devices and encrypted backups keep full
copies — but share a server with people you'd trust not to vandalise it.

### Adding a second device (or joining someone's server)

1. On a device that already has the vault, open **Settings → Sync** and copy the
   **Vault ID** (and the access token, if that server uses one).
2. On the new device, open the app. On the lock screen choose **Connect**, paste
   the Vault ID (and token), and continue. The encrypted vault downloads.
3. Enter your **master password** to unlock. That's it — edits now sync both
   ways.

On the lock screen you can instead **Start a new vault**, which mints a fresh
Vault ID. Every vault syncs: the server is the vault's off-device backup, and
browser storage alone is too easy to lose. The app still works with the server
unreachable and catches up when it returns.

## Sync, conflicts, and backup

- **Per-entry sync.** Edits to different entries on different devices merge
  silently. Only a genuine same-entry conflict stops to ask you — it shows both
  versions and stays flagged until you pick one. Connected devices are nudged to
  re-sync in real time over the server's SSE channel.
- **Offline.** Add/edit/delete offline; it all syncs on reconnect. The UI warns
  you not to stay offline indefinitely, because the browser can clear its
  storage.
- **Encrypted backup.** Settings → Backup exports the whole vault as an
  encrypted file (openable only with the master password that made it) and
  imports one back. Works fully offline. On import the backup wins: it overwrites
  matching server entries and revives ones it had deleted, while entries that
  exist only on the server are kept. The file also records your (non-secret)
  Vault ID, so restoring reattaches to the same server vault (see Recovery).
- **Emergency recovery sheet.** Mark your truly critical, rarely-changing
  entries — crypto seed phrases, master passwords, 2FA backup codes — as
  *critical* on their Edit screen. Then Settings → *Emergency recovery sheet*
  prints just those to paper via the browser's print dialog (`window.print()`,
  no PDF file). An offline last resort that device failure, ransomware, or
  cleared browser storage can't touch. It's plaintext by design: you're warned
  first, values print in monospace so seed words and codes transcribe
  unambiguously, and the paper is the only copy created. Store it somewhere
  physically secure, shred old copies, and use a printer you trust — shared or
  networked printers can retain what they print.

## Recovery — when things go wrong

Three things stand between you and your passwords. Know which are recoverable:

| Thing | Secret? | Recoverable? |
| --- | --- | --- |
| **Master password** | Yes — never stored anywhere | **No.** There is no reset. Forget it and the data is gone, everywhere. |
| **Vault ID** | No (an unguessable random id) | Only from a device that still has the vault, or from a backup file — **never from the server**, which won't list vaults. |
| **Your data** | Encrypted at rest | Yes, *if* you can supply the two above. |

The server intentionally has **no "list my vaults" endpoint** — that would let a
stranger enumerate everyone's data. So it stores your Vault ID but will never
hand it back; you have to present it. Plan your recovery around that:

- **Lost one device, still have another.** Nothing to do — read the Vault ID
  from the surviving device (Settings → Sync), and on the replacement choose
  **Connect**, paste it, and unlock. You're back.
- **Lost every device, but have a backup file.** On a fresh install, the lock
  screen has **"Restore from a backup file"** (on both the Connect and Create
  screens). Pick your export, then unlock with that backup's master password.
  The backup is fully self-contained — it recovers your data **without the
  server and without separately knowing the Vault ID** — and because a v2 backup
  records the Vault ID, the restored device reattaches to the same server vault
  and keeps syncing with anything still alive.
- **Lost everything — no other device, no backup, no saved Vault ID.** Your
  (encrypted) data may still sit on the server, but you can't tell it which blob
  is yours, so it is effectively unrecoverable **even with the master
  password.** Don't let yourself land here.

**So, minimum safe practice:** never forget the master password, and keep an
encrypted backup somewhere safe (cloud drive, USB stick — it's ciphertext).
A backup makes the Vault ID a non-issue for recovery; without one, server sync
alone is not a backup. For the handful of secrets you absolutely cannot lose,
also print an **emergency recovery sheet** (above) — paper survives things that
take out every digital copy at once.

> The Vault ID isn't a password — it's fine to write it down or store it in
> plain sight. The master password is the only true secret.

## HTTPS / testing on a phone

The service worker (offline + PWA install) only runs on `localhost` or over
HTTPS. For phones on your LAN this project uses mkcert: if `certs/cert.pem` and
`certs/key.pem` exist, the server also listens on HTTPS (`-tlsaddr`, default
`:8443`).

```sh
mkcert -cert-file certs/cert.pem -key-file certs/key.pem \
  192.168.1.110 localhost 127.0.0.1 ::1   # rerun with your machine's LAN IPs
```

Phone setup (once): AirDrop `mkcert-rootCA.crt` (a copy of
`$(mkcert -CAROOT)/rootCA.pem`) to the phone, install it under Settings →
General → VPN & Device Management, then enable full trust under Settings →
General → About → Certificate Trust Settings. The phone trusts the *CA*, so
regenerated certs (e.g. adding an IP) need no further phone changes. For a
public deployment, use a real certificate (Let's Encrypt / Caddy) instead.

## Project layout

- `main.go` — the whole server: serves the embedded PWA and the `/api/*` sync
  endpoints, stores client ciphertext in SQLite (one namespace per Vault ID),
  and broadcasts change notifications over `/events` (SSE).
- `web/` — the PWA, embedded into the binary at build time:
  - `js/vault.js` — all crypto + IndexedDB (DOM-free, reusable).
  - `js/sync.js` — HTTP sync orchestration and the Vault ID / token config.
  - `js/vaultui.js` — the lock gate, list/search, record modal, conflict UI.
  - `js/app.js` — app-shell chrome (drawer, routing, reachability).
- `extension/` — the Chrome companion; `make extension` assembles it.
- `site/` — the public website, a separate Go module (see below).

## Browser extension

The PWA can't autofill other pages — that needs an extension. `extension/`
holds a Chrome (MV3) companion that reuses the same vault modules verbatim:
connect it to your server with the Vault ID and token, unlock with the
master password, and it shows matches for the current site, fills the login
form on click, and copies passwords and verification codes (passwords with
the same auto-clearing clipboard). It is read-only by design — add and edit
entries in the app.

To build and install: `make extension`, then **chrome://extensions** →
enable Developer mode → **Load unpacked** → pick `dist/extension`.

## Website

`site/` is the public website: a landing page explaining what the app does,
and a contact form that sends through `github.com/hammondus/mailer`. It is a
**separate Go module** with its own `Makefile`, `Dockerfile`, and
`docker-compose.yaml`, so it deploys on its own schedule and keeps the mailer
dependency out of the vault server. Run its commands from `site/`:

```sh
cd site
make run          # http://localhost:8090, files served from disk
make shots        # regenerate the app screenshots (needs the app on :8080)
make deploy       # on the server: pull, build, restart, smoke-test
```

The site has no JavaScript; the contact form is a plain POST. With no SMTP
host configured, messages are logged instead of sent, so the whole path runs
locally. See `site/README.md` for the flags, the anti-spam layers, and the
mail environment variables.

## Non-goals

- **Native-app autofill on phones.** The extension covers desktop browsers;
  iOS/Android system autofill needs a native app, and the PWA instead leans
  into what it does well: fast offline access, install-to-homescreen, and
  copy buttons that auto-clear the clipboard.
