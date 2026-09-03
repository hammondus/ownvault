# ownvault — zero-knowledge password vault: Go server + PWA in web/.
# Deploys as a container behind Nginx Proxy Manager (NPM terminates TLS; the
# container serves plain HTTP). See DEPLOY.md for the staging/promote runbook.

BINARY := ownvault

# Static, stripped builds; pure Go (modernc sqlite), so CGO off everywhere.
GOFLAGS := -trimpath
LDFLAGS := -s -w

# Deferred (`=`, not `:=`) so targets that don't need git never shell out for
# it. -dirty marks a tree with uncommitted changes: such a tag describes no
# commit, and docker-build warns about it.
REV = $(shell git rev-parse --short=12 HEAD 2>/dev/null)$(shell git diff --quiet HEAD 2>/dev/null || echo -dirty)
PROD_URL = $(shell grep -m1 '^OWNVAULT_URL=' .env 2>/dev/null | cut -d= -f2-)
STAG_URL = $(shell grep -m1 '^OWNVAULT_STAGING_URL=' .env 2>/dev/null | cut -d= -f2-)
DEMO_URL = $(shell grep -m1 '^OWNVAULT_DEMO_URL=' .env 2>/dev/null | cut -d= -f2-)

# Rewrite one KEY=VALUE in .env, preserving every other line. awk rather than
# `sed -i`, whose in-place flag is spelled differently on macOS and Linux.
define set_env_var
	@touch .env
	@awk -v k='$(1)' -v v='$(2)' -F= '$$1==k{next} {print} END{print k"="v}' .env > .env.new && mv .env.new .env
endef

.PHONY: build test run release clean extension version \
        version-patch version-minor version-major \
        docker-build deploy deploy-built deploy-staging deploy-staging-built \
        promote rollback images smoke smoke-staging smoke-demo \
        deploy-demo stop-demo logs logs-staging logs-demo

# Bump one field of the semver in ./VERSION. That file is the only place a
# version lives: the Go binary embeds it, /js/version.js hands it to the
# browser, and the service worker keys its cache on it. awk rather than
# `sed -i`, whose in-place flag differs between macOS and Linux.
define bump_version
	@test -f VERSION || echo 0.0.0 > VERSION
	@awk -F. -v part='$(1)' '{ \
		major=$$1; minor=$$2; patch=$$3; \
		if (part=="major") { major++; minor=0; patch=0 } \
		else if (part=="minor") { minor++; patch=0 } \
		else { patch++ } \
		printf "%d.%d.%d\n", major, minor, patch \
	}' VERSION > VERSION.new && mv VERSION.new VERSION
	@echo "VERSION -> $$(cat VERSION)"
endef

## version: print the current version
version:
	@cat VERSION

## version-patch: bump the patch field (every shipped change gets at least this)
version-patch:
	$(call bump_version,patch)

## version-minor: bump the minor field — new user-visible capability
version-minor:
	$(call bump_version,minor)

## version-major: bump the major field — a break users must be told about
version-major:
	$(call bump_version,major)

## build: compile the server binary for this machine (web/ embedded)
build:
	go build $(GOFLAGS) -o $(BINARY) .

## test: vet + tests (JS crypto/UI is exercised by the verify skill, not here)
test:
	go vet ./...
	go test ./...

## run: dev server — serves web/ from disk, edit + refresh, throwaway DB
run:
	go run . -dev -db /tmp/ownvault-dev.db

## release: cross-compiled static binaries into dist/
# linux/arm64 is the container deploy target (belt and braces — the image
# builds its own binary); the rest serve the documented "desktop only" mode,
# where a person runs the server on their own machine with no Docker at all.
release:
	rm -rf dist
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe .

## clean: remove build output
clean:
	rm -rf $(BINARY) dist

## extension: assemble the Chrome extension into dist/extension
# The extension reuses the PWA's crypto/storage/sync modules VERBATIM —
# web/js is the single source of truth, and this copy step (not checked-in
# copies) is what keeps it that way. Load via chrome://extensions ->
# "Load unpacked" -> dist/extension; re-run this target after edits.
EXT_SHARED = web/js/vault.js web/js/totp.js web/js/sync.js web/js/argon2.min.js
extension:
	rm -rf dist/extension
	mkdir -p dist/extension/shared dist/extension/icons
	cp extension/* dist/extension/
	# Chrome demands a version in the manifest and can't read VERSION at
	# runtime, so stamp it here. The checked-in literal is a placeholder;
	# overwriting the copy keeps VERSION the only number anyone edits.
	sed 's/"version": "[^"]*"/"version": "'"$$(cat VERSION)"'"/' \
	  extension/manifest.json > dist/extension/manifest.json
	cp $(EXT_SHARED) dist/extension/shared/
	cp web/icons/icon-192.png web/icons/icon-512.png dist/extension/icons/
	@echo "built dist/extension — load it unpacked from chrome://extensions"

## docker-build: build the container image for the current revision
docker-build:
	@test -n "$(REV)" || { echo "no git revision — build from a git checkout"; exit 1; }
	@case "$(REV)" in *-dirty) echo "WARNING: building from a DIRTY tree as ownvault:$(REV) — this tag describes no commit";; esac
	docker build -t ownvault:$(REV) .

## deploy-staging: pull, build this revision, run it as staging, smoke-test
# The pull is its own line and the rest is a sub-make: make expands a recipe
# in full before running any of it, so $(REV) inline here would resolve
# against the PRE-pull HEAD (the trap primed's Makefile documents).
deploy-staging:
	git pull
	@$(MAKE) --no-print-directory deploy-staging-built

## deploy-staging-built: stage the CURRENT tree, no pull
# The escape hatch for testing a branch or a hotfix edited on the box —
# `deploy-staging` would pull straight over either.
deploy-staging-built: docker-build
	$(call set_env_var,OWNVAULT_STAGING_TAG,$(REV))
	docker compose --profile staging up -d ownvault-staging
	@echo "staging now on ownvault:$(REV)"
	@$(MAKE) --no-print-directory smoke-staging

## promote: point PRODUCTION at the image staging is running. No rebuild.
promote:
	@tag=$$(grep -m1 '^OWNVAULT_STAGING_TAG=' .env | cut -d= -f2-); \
	test -n "$$tag" || { echo "no OWNVAULT_STAGING_TAG in .env — run 'make deploy-staging' first"; exit 1; }; \
	docker image inspect ownvault:$$tag >/dev/null 2>&1 || { echo "image ownvault:$$tag is gone — rebuild with 'make deploy-staging'"; exit 1; }; \
	prev=$$(grep -m1 '^OWNVAULT_TAG=' .env | cut -d= -f2-); \
	echo "promoting ownvault:$$tag to production (rollback with: make rollback TAG=$$prev)"; \
	$(MAKE) --no-print-directory rollback TAG=$$tag

## rollback: point production at any built tag — make rollback TAG=<sha>
# Also the engine behind `promote`: a promotion and a rollback are the same
# operation pointed at different tags.
rollback:
	@test -n "$(TAG)" || { echo "usage: make rollback TAG=<sha>   (see 'make images')"; exit 1; }
	@docker image inspect ownvault:$(TAG) >/dev/null 2>&1 || { echo "no image ownvault:$(TAG) — see 'make images'"; exit 1; }
	$(call set_env_var,OWNVAULT_TAG,$(TAG))
	docker compose up -d ownvault
	@$(MAKE) --no-print-directory smoke

## deploy: build and go straight to production, skipping staging
# For config-only changes or fixes already proven. Prefer deploy-staging +
# promote: this ships an image no instance has run.
deploy:
	git pull
	@$(MAKE) --no-print-directory deploy-built

deploy-built:
	@$(MAKE) --no-print-directory docker-build
	@$(MAKE) --no-print-directory rollback TAG=$(REV)

## deploy-demo: run (or re-point) the public demo on production's image
# No build and no tag of its own: the demo runs whatever OWNVAULT_TAG names, so
# it always shows the build production is serving. `make promote` does not
# recreate it, so run this after promoting to bring the demo along.
#
# That coupling has a bootstrap consequence: until a build carrying -demo has
# been promoted, production's image does not know the flag and the container
# exits at startup with "flag provided but not defined: -demo". Compose reports
# that as a started service and `smoke-demo` as "not answering", neither of
# which names the cause — so prove the image supports the flag BEFORE starting
# anything. `-h` lists the flags a binary has, which is a positive check: if
# the probe itself breaks, it refuses to deploy rather than passing quietly.
deploy-demo:
	@grep -q '^OWNVAULT_TAG=..*' .env 2>/dev/null || { echo "no OWNVAULT_TAG in .env — deploy production first (see DEPLOY.md)"; exit 1; }
	@tag=$$(grep -m1 '^OWNVAULT_TAG=' .env | cut -d= -f2-); \
	docker image inspect ownvault:$$tag >/dev/null 2>&1 || { echo "image ownvault:$$tag is gone — rebuild with 'make deploy-staging'"; exit 1; }; \
	docker run --rm ownvault:$$tag -h 2>&1 | grep -q '^  -demo$$' || { \
	  echo "ownvault:$$tag predates the -demo flag, so the demo would exit at startup."; \
	  echo "The demo runs production's image, so promote a build that has the flag first:"; \
	  echo "    make deploy-staging && make promote && make deploy-demo"; \
	  exit 1; }
	docker compose --profile demo up -d ownvault-demo
	@$(MAKE) --no-print-directory smoke-demo

## stop-demo: take the demo down (its vaults go with the volume only if you
## also remove ownvault-demo-data, which nothing here does)
stop-demo:
	docker compose --profile demo stop ownvault-demo

## images: the tags available to promote or roll back to, newest first
images:
	@docker images ownvault --format '{{.Tag}}\t{{.CreatedSince}}\t{{.Size}}' | grep -v '^<none>' | head -20

## smoke: production answers over its public URL, as the vault
# The root path serves the app shell, so a 200 proves NPM -> container -> Go
# server end to end. Retries cover the container's startup moment.
#
# Three things the obvious `curl -sf URL` gets wrong here:
#
#   - A URL without a scheme makes curl assume http://, and `-f` treats the
#     resulting 301 as success. The case guard rejects it outright.
#   - Without -L, any redirect passes without the destination being fetched.
#   - A 200 alone does not prove the VAULT answered. The website shares this
#     box and serves an identical `ok` on /healthz, so a misrouted proxy host
#     smoke-tests green. Matching the CSP identifies the service, and confirms
#     the header survived the proxy. 'wasm-unsafe-eval' appears only in
#     vaultCSP (main.go); the site's CSP says script-src 'none'.
#
# A 200 carrying the wrong CSP fails immediately rather than retrying: that is
# a routing mistake, and waiting will not fix it.
smoke:
	@test -n "$(PROD_URL)" || { echo "set OWNVAULT_URL in .env to smoke-test"; exit 0; }
	@case "$(PROD_URL)" in http://*|https://*) ;; *) \
	  echo "OWNVAULT_URL must include the scheme, e.g. https://$(PROD_URL)"; exit 1;; esac
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
	  h=$$(curl -sL -m 10 -o /dev/null -D - -w "status=%{http_code}" "$(PROD_URL)/" 2>/dev/null); \
	  case "$$h" in *status=200) ;; *) sleep 2; continue;; esac; \
	  case "$$h" in *"wasm-unsafe-eval"*) echo "smoke ok: $(PROD_URL)"; exit 0;; esac; \
	  echo "SMOKE FAILED: $(PROD_URL) answered 200 but is not the vault (CSP mismatch) — check the NPM proxy host"; exit 1; \
	done; echo "SMOKE FAILED: $(PROD_URL)/ not answering"; exit 1

## smoke-staging: same check against the staging URL
smoke-staging:
	@test -n "$(STAG_URL)" || { echo "set OWNVAULT_STAGING_URL in .env to smoke-test"; exit 0; }
	@case "$(STAG_URL)" in http://*|https://*) ;; *) \
	  echo "OWNVAULT_STAGING_URL must include the scheme, e.g. https://$(STAG_URL)"; exit 1;; esac
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
	  h=$$(curl -sL -m 10 -o /dev/null -D - -w "status=%{http_code}" "$(STAG_URL)/" 2>/dev/null); \
	  case "$$h" in *status=200) ;; *) sleep 2; continue;; esac; \
	  case "$$h" in *"wasm-unsafe-eval"*) echo "smoke ok: $(STAG_URL)"; exit 0;; esac; \
	  echo "SMOKE FAILED: $(STAG_URL) answered 200 but is not the vault (CSP mismatch) — check the NPM proxy host"; exit 1; \
	done; echo "SMOKE FAILED: $(STAG_URL)/ not answering"; exit 1

## smoke-demo: the demo answers, and answers AS the demo
# Checking the shell like the other two would pass against production, whose
# proxy host is one line away in the same NPM config. /js/version.js carries
# APP_DEMO only when the server was started with -demo, so this proves the
# instance and its flag at once — a demo silently running without the flag
# would take no caps, no creation limits, and no expiry.
smoke-demo:
	@test -n "$(DEMO_URL)" || { echo "set OWNVAULT_DEMO_URL in .env to smoke-test"; exit 0; }
	@case "$(DEMO_URL)" in http://*|https://*) ;; *) \
	  echo "OWNVAULT_DEMO_URL must include the scheme, e.g. https://demo.ownvault.example"; exit 1;; esac
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
	  body=$$(curl -sL -m 10 "$(DEMO_URL)/js/version.js" 2>/dev/null); \
	  case "$$body" in *APP_VERSION*) ;; *) sleep 2; continue;; esac; \
	  case "$$body" in *APP_DEMO*) echo "smoke ok: $(DEMO_URL) (demo mode on)"; exit 0;; esac; \
	  echo "SMOKE FAILED: $(DEMO_URL) is serving the vault but NOT in demo mode — it is production, or the -demo flag is missing"; exit 1; \
	done; echo "SMOKE FAILED: $(DEMO_URL)/ not answering"; exit 1

## logs: follow production logs
logs:
	docker compose logs -f ownvault

## logs-staging: follow staging logs
logs-staging:
	docker compose --profile staging logs -f ownvault-staging

## logs-demo: follow demo logs (the hourly sweep reports here)
logs-demo:
	docker compose --profile demo logs -f ownvault-demo
