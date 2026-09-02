# Multi-stage build for the Own Vault website. Same shape as the vault
# server's Dockerfile at the repository root, but a different module: this
# image carries the mailer dependency and no SQLite, and the two deploy
# independently.
#
# The build context is site/, not the repository root — the site module is
# self-contained and has no reason to see the vault server's source.

FROM golang:1.26 AS build
WORKDIR /src

# Module files first, source second: the dependency download caches as its own
# layer and only re-runs when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# web/ and templates/ are embedded by go:embed at build time. The -dev
# disk-serving path exists only for local editing and is never used here.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ovsite .

# Pure Go, so the binary is fully static and drops into distroless "static":
# no libc, no shell, nothing to exec if the process is ever subverted.
FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=build /out/ovsite /app/ovsite

EXPOSE 8090

# The binary probes itself. Distroless has no shell and no curl, so the usual
# CMD-SHELL probe is impossible; -healthcheck dials loopback on the listen
# address and exits by the result. Exec form for the same reason — there is no
# shell to parse the string form — which is also why -addr is repeated here
# rather than inherited from CMD.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/ovsite", "-healthcheck", "-addr", ":8090"]

ENTRYPOINT ["/app/ovsite"]
CMD ["-addr", ":8090"]
