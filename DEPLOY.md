# Deploying ownvault

The server ships as a container behind Nginx Proxy Manager. NPM terminates
TLS; the container serves plain HTTP on 8080. Two instances run from one
image — production and an opt-in staging copy — following the primed
deploy pattern: staging proves an image, `promote` points production at that
exact image, `rollback` is a container swap.

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

4. In NPM, add two proxy hosts, both plain `http` upstreams:
   - production hostname → `ownvault:8080`
   - staging hostname → `ownvault-staging:8080`

   Enable **HSTS** on both: the app only sends it from its own (unused here)
   TLS listener, so behind NPM nobody sends it unless NPM does. Websockets
   support is not needed — sync notifications are SSE, and the server sets
   `X-Accel-Buffering: no` so nginx streams them unbuffered.

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

## Day to day

```sh
make deploy-staging       # pull, build ownvault:<sha>, run as staging, smoke
make promote              # production runs the exact image staging proved
make rollback TAG=<sha>   # container swap to any built tag (see make images)
make deploy               # build straight to production (skips staging)
make logs                 # follow production logs
make deploy-staging-built # stage the current tree without pulling (hotfix/branch)
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
