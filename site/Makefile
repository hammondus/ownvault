# Own Vault website — Go server + templates + web/ in this directory.
# Its own module, so run every target from site/, not the repository root.
# Deploys as a container behind Nginx Proxy Manager; see README.md.

BINARY := ovsite

GOFLAGS := -trimpath
LDFLAGS := -s -w

# Deferred (`=`, not `:=`) so targets that never need git don't shell out for
# it. -dirty marks a tree with uncommitted changes: such a tag describes no
# commit, and docker-build warns about it.
REV = $(shell git rev-parse --short=12 HEAD 2>/dev/null)$(shell git diff --quiet HEAD 2>/dev/null || echo -dirty)
SITE_URL = $(shell grep -m1 '^OVSITE_URL=' .env 2>/dev/null | cut -d= -f2-)

# Rewrite one KEY=VALUE in .env, preserving every other line. awk rather than
# `sed -i`, whose in-place flag is spelled differently on macOS and Linux.
define set_env_var
	@touch .env
	@awk -v k='$(1)' -v v='$(2)' -F= '$$1==k{next} {print} END{print k"="v}' .env > .env.new && mv .env.new .env
endef

.PHONY: build test run release clean docker-build deploy deploy-built smoke logs shots

## build: compile the site binary for this machine (web/ + templates/ embedded)
build:
	go build $(GOFLAGS) -o $(BINARY) .

## test: vet + tests
test:
	go vet ./...
	go test ./...

## run: dev server on :8090, serving web/ and templates/ from disk
# With no SMTP configured the mailer logs each message instead of sending it,
# so the whole contact path runs without a mail account.
run:
	go run . -dev -addr :8090 -to you@example.com

## release: cross-compiled static binaries into dist/
# linux/arm64 is the container deploy target (belt and braces — the image
# builds its own binary); the others cover running the site on a desktop box.
release:
	rm -rf dist
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 .

## clean: remove build output
clean:
	rm -rf $(BINARY) dist

## docker-build: build the container image for the current revision
docker-build:
	@test -n "$(REV)" || { echo "no git revision — build from a git checkout"; exit 1; }
	@case "$(REV)" in *-dirty) echo "WARNING: building from a DIRTY tree as ovsite:$(REV) — this tag describes no commit";; esac
	docker build -t ovsite:$(REV) .

## deploy: on the server — pull, build this revision, run it, smoke-test
# The pull is its own line and the rest is a sub-make: make expands a recipe
# in full before running any of it, so $(REV) inline here would resolve
# against the pre-pull HEAD.
deploy:
	git pull
	@$(MAKE) --no-print-directory deploy-built

## deploy-built: deploy the CURRENT tree, no pull
deploy-built: docker-build
	$(call set_env_var,OVSITE_TAG,$(REV))
	docker compose up -d ovsite
	@$(MAKE) --no-print-directory smoke

## smoke: the site answers over its public URL
smoke:
	@test -n "$(SITE_URL)" || { echo "set OVSITE_URL in .env to smoke-test"; exit 0; }
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
	  curl -sf -m 10 -o /dev/null "$(SITE_URL)/healthz" && { echo "smoke ok: $(SITE_URL)"; exit 0; }; sleep 2; \
	done; echo "SMOKE FAILED: $(SITE_URL)/healthz not answering"; exit 1

## logs: follow the site's logs
logs:
	docker compose logs -f ovsite

## shots: regenerate the app screenshots in web/img
# Deliberately not wired into build or deploy: it needs the vault server
# running, drives a real browser, and is only worth running when the app's UI
# has actually changed. Playwright is a dev-only tool — installed on demand
# here, never a dependency of the site itself.
#
# Start the app first, in the repository root:  go run . -dev
shots:
	@command -v node >/dev/null || { echo "node is required for 'make shots'"; exit 1; }
	@curl -sf -m 3 -o /dev/null http://localhost:8080/ || { echo "the app is not on :8080 — run 'go run . -dev' in the repository root"; exit 1; }
	@test -d node_modules/playwright || npm install --no-save playwright
	npx playwright install chromium
	node tools/shots.js web/img
	@echo "screenshots rewritten in web/img — check them before committing"
