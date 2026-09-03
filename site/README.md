# Own Vault website

The public site for Own Vault: a landing page that explains what the app does,
and a contact form. It is a separate Go module from the vault server, with its
own `Makefile`, `Dockerfile`, and `docker-compose.yaml`.

Run every command in this document from `site/`, not from the repository root.

## Why it is a separate module

The vault server at the repository root is the zero-knowledge sync point. It
has no business carrying an SMTP client, a template set, or marketing copy, and
a copy edit here must never restart a container people are syncing vaults
through. Nesting a `go.mod` in `site/` removes this directory from the parent
module automatically, so `go build ./...` at the root never picks it up and
`github.com/hammondus/mailer` stays out of the vault server's dependency tree.

The site has **no JavaScript at all**. The contact form is a plain HTML POST,
which is why the Content-Security-Policy can set `script-src 'none'` — an
injected `<script>` has nothing to run in.

## Run it locally

```sh
make run          # http://localhost:8090, files served from disk
```

`-dev` serves `web/` and `templates/` from disk and re-parses templates on
every request, so edit and refresh. Without it, both are embedded by
`go:embed` and the binary is self-contained.

With no SMTP host configured, `mailer` logs each composed message instead of
sending it. The whole contact path still runs — validation, anti-spam, rate
limiting, composition — and the message body appears in the server log. That is
the intended way to work on the form.

Flags:

| Flag | Default | What it does |
| --- | --- | --- |
| `-addr` | `:8090` | HTTP listen address |
| `-dev` | off | serve `web/` and `templates/` from disk |
| `-to` | `$OWNVAULT_SITE_CONTACT_TO` | destination for contact mail |
| `-baseurl` | empty | public origin, for the canonical and `og:` tags |
| `-repo` | the GitHub URL | repository the links point at |
| `-trusted-proxies` | `private` | peers whose `X-Forwarded-For` is believed |
| `-healthcheck` | off | probe a running server's `/healthz` and exit |

`-trusted-proxies` decides which client address the rate limiter counts
against. `private` covers loopback and private space, which is the deployed
shape: Nginx Proxy Manager on a Docker network. Pass a comma-separated list of
CIDRs or addresses to name the proxy exactly, or an empty string if the site is
ever exposed directly — then `X-Forwarded-For` is ignored and the peer address
is used. An untrusted peer's header is never believed, and the header is read
from the right, so a forged value cannot push the real client out of its
bucket.

`-healthcheck` backs the container `HEALTHCHECK`: the distroless image has no
shell, so the binary probes itself.

Mail is configured entirely by environment: see `.env.example`.

## Anti-spam

Four layers, none of which asks a visitor to identify traffic lights:

- A **honeypot** field, positioned off-screen rather than `display: none`,
  because some bots skip fields that are not rendered. A filled honeypot gets
  the success page, so the bot learns nothing.
- A **signed timestamp** in every rendered form. Submissions faster than three
  seconds are automation; forms older than two hours have expired. The HMAC is
  what stops a bot minting its own timestamp. The key is generated per process,
  so a restart invalidates open forms — a fair trade for having no secret in
  configuration.
- **Three submissions per IP per hour**, as a sliding log.
- A **64 KiB body cap**, so one request cannot fill memory.

## Deploy

Same shape as the vault server: build a tagged image on the box, point compose
at the tag, smoke-test.

```sh
cp .env.example .env    # first time only: fill in SMTP and the destination
make deploy             # git pull, build ovsite:<sha>, restart, smoke-test
make logs
```

Nginx Proxy Manager terminates TLS and proxies to `ovsite:8090` on the shared
`blobbyboo` network. The compose file publishes no ports. For the proxy host
settings, and for the `www.` redirect that keeps one canonical origin, see
"Nginx Proxy Manager" in the vault server's DEPLOY.md — one NPM instance fronts
both. Set `OVSITE_URL` to the canonical name, since it fills the canonical and
`og:` tags and is what `make smoke` probes.

`make deploy-built` skips the pull, for testing a branch or a fix edited on the
box.

## Regenerating the screenshots

`web/img/*.png` are real screens of the real app, filled with invented logins.
To rebuild them after a UI change:

```sh
cd .. && go run . -dev &   # the app on :8080
cd site && make shots
```

`tools/shots.js` creates a fresh vault in a throwaway browser profile, adds the
demo entries through `Vault.put`, and captures each screen. It installs
Playwright on demand; that is a dev-only tool and never a dependency of the
site. The final resize uses `sips`, which is macOS-only — on another platform,
resize the PNGs to 700px wide by whatever means is at hand.

Check the results before committing. The script asks a browser to lay out a
page, which is not a thing that produces identical bytes twice.

## Caching

Set per resource, per the house rule:

- HTML: `no-cache`. A page carries the URLs of every asset it references, so
  serving it stale would defeat the hashing below.
- `style.css` and the images: referenced with a `?v=<hash>` of the file
  contents, and anything carrying a `?v=` is `public, max-age=31536000,
  immutable`.
- Anything requested without a `?v=` gets an hour, since that URL's content can
  change under a client.

The hash is computed once at startup, which is correct because the files are
embedded at build time. In `-dev` they are read from disk, so the hash is
skipped there and `no-cache` does the work.
