# Multi-stage build for the ownvault server. Pure Go (modernc.org/sqlite, no
# CGo), so the binary is fully static and drops into a distroless "static"
# base — no libc, no shell, minimal attack surface. web/ is embedded by
# go:embed at build time (the -dev disk-serving path is dev-only), so the
# image carries a single binary plus an empty /data mount point.
#
# The build stage runs on the deploy host under `make docker-build`
# (arm64 on the arm64 box), so `go build` produces the right arch with no
# explicit cross-compile here. `make release` covers cross-compiled binaries.

FROM golang:1.26 AS build
WORKDIR /src

# Module files first, source second: dependency downloads cache as their own
# layer and only re-run when go.mod/go.sum change, not on every code edit.
COPY go.mod go.sum ./
RUN go mod download

# .dockerignore keeps certs/ out of the context. That is a functional
# exclusion, not tidiness: the server starts its TLS listener whenever
# certs/cert.pem + key.pem exist, and behind Nginx Proxy Manager (which
# terminates TLS) that listener would also arm the plain-HTTP-to-HTTPS
# redirect and break every proxied request. No certs in the image means the
# container is plain HTTP on 8080, which is exactly what NPM proxies to.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ownvault .

# Pre-create the SQLite directory so the runtime stage can install it with
# the right owner (below). 0700: the DB is ciphertext, but there is no reason
# for it to be readable by anything but the server.
RUN mkdir -m 0700 /out/data

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=build /out/ownvault /app/ownvault

# /data must exist in the image WITH nonroot ownership: a fresh named volume
# copies the ownership of the image directory it mounts over, and without
# this the volume initializes root-owned — which the nonroot (uid 65532)
# process cannot write, so the very first startup dies creating the DB.
COPY --from=build --chown=nonroot:nonroot /out/data /data

EXPOSE 8080

# The binary probes itself. Distroless has no shell and no curl, so the usual
# CMD-SHELL probe is impossible; -healthcheck dials loopback on the listen
# address and exits by the result. Exec form for the same reason — there is no
# shell to parse the string form — which is also why -addr is repeated here
# rather than inherited from CMD.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/ownvault", "-healthcheck", "-addr", ":8080"]

ENTRYPOINT ["/app/ownvault"]
# -db is not optional: the flag default puts the DB next to the executable,
# which here is the image's read-only layer, not the volume.
CMD ["-addr", ":8080", "-db", "/data/ownvault.db"]
