# Deploying ownvault

The server ships as a container behind Nginx Proxy Manager. NPM terminates
TLS; the container serves plain HTTP on 8080. Two instances run from one
image — production and an opt-in staging copy — following the primed
deploy pattern: staging proves an image, `promote` points production at that
exact image, `rollback` is a container swap.

The website is a separate module with its own container, its own compose file,
and its own runbook in `site/README.md`. It shares the box, the same Docker
network, and this NPM instance, so its proxy hosts are documented here
alongside the vault's.

## First-time setup (on the deploy host)

1. Clone the repo and copy the config:

   ```sh
   git clone <repo> && cd ownvault
   cp .env.example .env
   ```

2. Set `OWNVAULT_TOKEN` in `.env` (`openssl rand -hex 16`). Set
   `OWNVAULT_STAGING_TOKEN` too if testers should never hold a
   production-capable token. Set `OWNVAULT_URL` / `OWNVAULT_STAGING_URL` so
   deploys smoke-test themselves.

3. The compose file joins the external `blobbyboo` network NPM lives on. If
   this host uses a different network name, change it in
   `docker-compose.yaml`.

4. In NPM, add the proxy hosts. For the hostnames, the upstreams, and the
   per-host settings, see [Nginx Proxy Manager](#nginx-proxy-manager).

5. First deploy: `make deploy`, straight to production. Not staging-first:
   Compose interpolates every service on any command, so production's
   "OWNVAULT_TAG must be set" guard fires before a first staging tag could
   satisfy it — and `make deploy` is what writes that tag. Shipping unstaged
   code is also harmless exactly once, while production has no users. From
   then on: `make deploy-staging`, check the staging hostname, `make promote`.

The PWA needs HTTPS at the browser edge for install and the service worker;
NPM's certificate satisfies that. The container must never contain `certs/`
(`.dockerignore` enforces it) — their presence would start the internal TLS
listener and its plain-HTTP redirect, which breaks proxied requests.

## Nginx Proxy Manager

One NPM instance fronts both the vault server and the website. Four hostnames,
in the shape this example uses:

| Hostname | NPM type | Forwards to | Serves |
|---|---|---|---|
| `ownvault.example` | Proxy Host | `ovsite` : `8090` | the website |
| `www.ownvault.example` | Redirection Host | `https://ownvault.example` | 301 to the canonical name |
| `app.ownvault.example` | Proxy Host | `ownvault` : `8080` | the vault |
| `staging.ownvault.example` | Proxy Host | `ownvault-staging` : `8080` | the staging vault |

Every upstream is plain `http`. Add the staging host only once the staging
container runs: a proxy host pointing at a stopped container answers 502 to the
public.

The vault gets its own hostname rather than a path under the website's, because
a browser origin is the scheme, host, and port — a path is not part of it. On
one hostname, the website could read the vault's IndexedDB and sync token. For
the rest of that reasoning, see DESIGN-DECISIONS.md "The vault and the website
are separate origins".

### Certificates

**A TLS wildcard matches exactly one label, and never a dot** (RFC 9525). So a
zone-level `*.example` certificate covers `ownvault.example` and stops there:

| Name | `*.example` | `*.ownvault.example` |
|---|---|---|
| `ownvault.example` | yes | no |
| `app.ownvault.example` | no | yes |
| `www.ownvault.example` | no | yes |
| `staging.ownvault.example` | no | yes |

A wildcard does not cover its own bare name either, so request **both
`*.ownvault.example` and `ownvault.example`** as two names on one certificate.
That single certificate then covers every host in the table above. A wildcard
needs a DNS-01 challenge, so NPM needs credentials for the DNS provider.

Single-name certificates work too, but each host then carries its own issuance
and renewal, and the failure below is what one missed host looks like.

The failure signature is misleading. The name resolves, plain HTTP answers 301,
and only the HTTPS leg fails — which reads as a proxy fault. It is a
certificate that does not cover the name:

```
Chrome:  ERR_CERT_COMMON_NAME_INVALID
curl:    (60) SSL: no alternative certificate subject name matches target host
```

To see which certificate a host actually serves, run:

```sh
echo | openssl s_client -servername <host> -connect <host>:443 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

**A Redirection Host has its own SSL tab.** Assigning a new certificate to the
Proxy Hosts leaves `www.` on whatever it had, and it then redirects visitors
into a certificate error.

### The vault hosts

`app.` and `staging.` take the same settings.

- **Force SSL** on, **HTTP/2** on.
- **HSTS off.** The server sends `Strict-Transport-Security` itself whenever a
  proxy reports that it terminated TLS (`hstsWhenProxied` in `main.go`, keyed
  on the `X-Forwarded-Proto: https` that NPM sets). Enabling NPM's as well
  sends the header twice and hides which layer owns the policy.
- **Websockets off.** Sync notifications are SSE, not websockets. The server
  sets `X-Accel-Buffering: no` so nginx streams them unbuffered, and the 25 s
  keepalive sits inside nginx's 60 s `proxy_read_timeout`.
- **Block Common Exploits off.** It matches request shapes this server does not
  have, and a false positive on an `/api/*` call reaches the client as a sync
  failure carrying no usable message.
- In the **Advanced** tab, set `client_max_body_size 10m;`. `maxPushBytes` is
  8 MiB, sized for a full-vault restore push, and stock nginx caps request
  bodies at 1 MiB. An nginx 413 surfaces in the client as an unexplained sync
  error, so set the limit rather than depending on NPM's default.

### The website hosts

- **Force SSL** on, **HTTP/2** on, **HSTS on.** The site sends no HSTS of its
  own, so NPM is the only source.
- **HSTS Subdomains** is safe to enable. It covers `www.` and `app.`, both of
  which are HTTPS-only. It does not reach a sibling such as
  `ownvault-staging.example`.
- Leave **HSTS Preload** off. Preload is a submission to a list compiled into
  browser binaries, and removal takes months.
- Add no header rules in the **Advanced** tab. The site sets `script-src
  'none'` itself, and an `add_header` in a nested nginx block discards the
  inherited headers instead of adding to them.

Use a Redirection Host for `www.`, not a second proxy host to the same
container. Two hostnames serving one site split the origin, so link shares,
caches, and the canonical and `og:` tags disagree with each other. Set
`OVSITE_URL` in `site/.env` to the name you keep.

### Verifying

```sh
curl -sI https://ownvault.example | grep -i 'strict-transport\|content-security'
curl -sI https://app.ownvault.example | grep -ci 'strict-transport'  # want 1
curl -sI https://www.ownvault.example | head -3                      # want 301
curl -sN https://app.ownvault.example/events | head -3               # want a stream
```

If the vault sends no HSTS header, NPM is not passing `X-Forwarded-Proto` and
`hstsWhenProxied` never fires. Check the proxy host, not the Go code.

## Changing the vault's hostname

A vault client keeps everything in the browser origin: IndexedDB, the sync
token, the service worker, and the PWA install. Changing the hostname is
therefore a new origin, and every device reconnects. Server data survives
untouched — entries are keyed by Vault ID, not by hostname — so a reconnected
device pulls its entries back down and keeps its Vault ID. Pick a hostname you
can live with, because the next change costs the same again.

Serve both names at once rather than swapping in one step:

1. Add an NPM proxy host for the new name, pointing at the same container. The
   vault now answers on both names, backed by one database.
2. On each device, export a backup from Settings. You should not need it. The
   reconnect is the step worth having a fallback for.
3. On each device, open the new name and connect with the setup code. Confirm
   your entries arrived before you go on.
4. Repoint or delete the old proxy host.
5. Unregister the old name's service worker in each browser
   (`chrome://serviceworker-internals`). Its scope is `/`, and its navigation
   fallback is the cached vault shell, so until it goes it can answer
   navigations to whatever serves that hostname next. A browser discards the
   registration by itself once `/sw.js` returns 404, but only on the update
   check, so the first navigation can still come from the old worker. Check
   rather than trust it.
6. Delete the old PWA installs and add them again from the new name. On iOS,
   delete the Home Screen icon first: the installed app has its own storage.
7. Update `OWNVAULT_URL` in `.env` so `make smoke` probes the new name.

The extension stores its server URL separately (`serverUrl` in `sync.js`) and
is single-vault, so repoint and reconnect it too.

## Day to day

```sh
make deploy-staging       # pull, build ownvault:<sha>, run as staging, smoke
make promote              # production runs the exact image staging proved
make rollback TAG=<sha>   # container swap to any built tag (see make images)
make deploy               # build straight to production (skips staging)
make logs                 # follow production logs
make deploy-staging-built # stage the current tree without pulling (hotfix/branch)
make deploy-demo          # run (or re-point) the public demo on production's image
make logs-demo            # follow demo logs — the hourly sweep reports here
```

## Staging is a separate vault world — by design

Each instance has its own SQLite volume (`ownvault-data`,
`ownvault-staging-data`); they must never share one. Staging starts empty:
connect a **throwaway test vault** to it, never your real one. The browser
enforces the same split — each hostname is its own origin with its own
IndexedDB, service worker, and PWA install — so nothing you do on staging
can touch a vault that lives on the production hostname, and vice versa.

To rehearse against realistic data, restore a backup file of a test vault
onto a device pointed at staging. Don't copy production's DB into staging's
volume as a habit: it works (the file is ciphertext; the write-auth
credential derives from the vault key, not the host), but then staging holds
real vaults' ciphertext and any device knowing the Vault ID + staging token
can write to them there.

## The public demo

`make deploy-demo` starts a third instance, `ownvault-demo`, on its own
hostname. It exists so somebody can try the app — including syncing between two
devices — without setting up a server. Anyone may create a vault on it, no
token required.

To set it up:

1. Add `OWNVAULT_DEMO_URL=https://demo.<your domain>` to `.env`.
2. Add a fourth Nginx Proxy Manager host pointing at `ownvault-demo:8080`, the
   same way the production and staging hosts are configured above.
3. Run `make deploy-demo`.

What the demo does differently, all of it driven by the `-demo` flag:

- Each vault holds at most 100 entries and 1 MB of ciphertext.
- The server holds at most 2000 vaults, and one address may create 10 a day.
- Every vault is deleted 7 days after its first write. A sweeper runs at
  startup and hourly; `make logs-demo` reports what it deleted.
- The app shows the warning and the deletion date on the lock screen, the app
  bar, and a Settings card.

Three operational points:

- **The demo runs `OWNVAULT_TAG`** — production's image — because a demo of an
  older build than the one being demoed is a bug. `make promote` does not
  recreate it, so run `make deploy-demo` after promoting.
- **`make smoke-demo` checks `/js/version.js` for `APP_DEMO`**, not the app
  shell. A shell check would pass against production, whose proxy host is one
  line away in the same NPM config, and a demo silently running without the
  flag would take no caps, no creation limits, and no expiry.
- **Its volume (`ownvault-demo-data`) is not worth backing up.** Everything in
  it is deleted after 7 days by design. Nothing that runs a DELETE on a timer
  shares a database with real vaults, which is why it has a volume of its own.

Deleting a vault removes it from the server, which is not the same as
destroying the data: a device that still holds it locally re-claims the id on
its next sync and the vault reappears. That is intended. The caps, not the
sweep, are what bound somebody determined to re-upload.

## Backups

The database is client-encrypted ciphertext end to end, so a plain file copy
is a safe backup:

```sh
docker run --rm -v ownvault-data:/data -v "$PWD":/out alpine \
  cp /data/ownvault.db /out/ownvault-backup.db
```

The copy is consistent only if taken while the container is stopped, or
accepted as crash-consistent (SQLite tolerates that). Users' own encrypted
export files (Settings → backup) are the primary recovery path; the server
copy protects the sync point itself.
