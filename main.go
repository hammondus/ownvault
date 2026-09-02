// A small server for the Own Vault PWA.
//
// Everything under web/ is embedded into the binary, so `go build` produces
// a single deployable file. Requests that match a real file are served as-is;
// any other path is an app route (/, /settings, ...) and gets the shell — the
// client then loads the matching fragment.
//
// The server also provides optional multi-device sync. It only ever stores
// and relays client-produced ciphertext (see CLAUDE.md) — it never sees
// plaintext or keys. Encrypted entries live in SQLite (pure-Go driver, so the
// single-binary/cross-compile story is preserved). Each write gets a
// server-assigned monotonic revision; clients pull everything past a cursor
// and push with optimistic concurrency so genuine same-entry conflicts are
// detected rather than silently overwritten.
//
// During development run with -dev to serve web/ from disk, so edits show up
// on refresh without rebuilding.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hammondus/nitrokit"
	_ "modernc.org/sqlite"
	"rsc.io/qr"
)

// Request-body caps for the sync API. The data is small by nature (a wrapped
// key record is a few hundred bytes; entries are a few KB of ciphertext), so
// generous limits still stop one client — on a shared server, one *tenant* —
// from filling the disk or RAM with a single oversized push.
const (
	maxMetaBytes = 64 << 10 // wrapped-key record
	maxPushBytes = 8 << 20  // full-vault restore push
)

// Cap on concurrent SSE connections so an unauthenticated client can't
// exhaust the server with idle /events streams (the endpoint is deliberately
// tokenless — see the /events handler).
const maxSSEClients = 256

// sseWriteBudget is how long a single write to a client may make no progress
// before the connection is killed. It replaces the server's WriteTimeout,
// which must be 0 on a server that streams (see newVaultServer).
const sseWriteBudget = 30 * time.Second

// Browser-side defence in depth, passed to nitrokit.SecureHeaders explicitly
// rather than taking its defaults: both defaults are wrong for this app.
const (
	// The policy can be strict because the app needs nothing exotic: all
	// scripts and styles are same-origin files (no inline, no eval — htmx 2
	// works without it). 'wasm-unsafe-eval' admits ONLY WebAssembly
	// compilation (the Argon2id KDF module), not JS eval, so the
	// string-to-code paths stay blocked. blob: appears twice: manifest-src for
	// the client-generated manifest carrying the vault name (see app.js), and
	// img-src for the setup-code QR, which arrives as an authenticated fetch
	// and is shown via an object URL (a plain <img src> can't carry the auth
	// header).
	vaultCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; " +
		"connect-src 'self'; manifest-src 'self' blob:; worker-src 'self'; " +
		"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

	// nitrokit's default denies camera outright, which would break the in-page
	// QR scanner that reads a setup code or a site's 2FA enrolment code
	// (vaultui.js startScan). Same-origin only; nothing is ever framed.
	vaultPermissions = "geolocation=(), camera=(self), microphone=(), interest-cohort=()"
)

// Token auth rate limiting: after authFailLimit failed token attempts from
// one IP within authFailWindow, further attempts from that IP get 429 until
// the window rolls over — and crucially, without running the compare, so an
// over-limit guess learns nothing. This turns "unlimited online guessing"
// into ~1k guesses/day per IP; a distributed attacker isn't stopped, which
// is the honest bar for a self-hosted binary (see DESIGN-DECISIONS.md).
const (
	authFailLimit  = 10
	authFailWindow = 15 * time.Minute
)

// minTokenLen rejects throwaway tokens at startup. The rate limiter above
// only slows guessing; the token's entropy is the real defence, and 16
// characters is the floor below which even limited guessing is a threat.
const minTokenLen = 16

//go:embed all:web
var embedded embed.FS

/* ==================== SSE broadcast hub ==================== */

// Fans "changed" notifications out to the clients watching a given vault so
// their other devices re-pull promptly. Each subscriber is tagged with the
// vault id it cares about, so one person's write never wakes an unrelated
// vault's clients on a shared server. Keepalive pings are per-connection (in
// the /events handler) and reach everyone regardless of tag — a reachability
// probe with no vault subscribes with the empty tag and still gets them.
type hub struct {
	mu      sync.Mutex
	clients map[chan string]string // channel -> vault id it watches
	done    chan struct{}          // closed to release every stream
}

func newHub() *hub {
	return &hub{clients: make(map[chan string]string), done: make(chan struct{})}
}

// close releases every open stream. A server-sent event response is an
// in-flight request as far as graceful shutdown is concerned, so without this
// each connected device would hold the whole drain budget on every restart.
// Registered with http.Server.RegisterOnShutdown; see main.
func (h *hub) close() { close(h.done) }

// add registers a subscriber, or returns nil when the server is already at
// its connection cap (the caller should reject the request).
func (h *hub) add(vault string) chan string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= maxSSEClients {
		return nil
	}
	ch := make(chan string, 8)
	h.clients[ch] = vault
	return ch
}

func (h *hub) remove(ch chan string) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *hub) broadcast(vault, msg string) {
	h.mu.Lock()
	for ch, v := range h.clients {
		if v != vault {
			continue
		}
		select {
		case ch <- msg:
		default: // slow client: drop; it will full-pull on its next sync
		}
	}
	h.mu.Unlock()
}

/* ==================== storage ==================== */

type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// modernc's driver is fine concurrently, but a single writer connection
	// sidesteps SQLite "database is locked" under our low, bursty load.
	db.SetMaxOpenConns(1)

	// Refuse to open a pre-namespacing database rather than silently ignoring
	// its data: the old schema had one global vault (entries keyed by id alone,
	// a single meta row). Those rows have no vault_id to migrate them under, so
	// we stop with a clear message instead of corrupting anything.
	var legacy int
	_ = db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='entries'`).Scan(&legacy)
	if legacy > 0 {
		var hasVID int
		_ = db.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='vault_id'`).Scan(&hasVID)
		if hasVID == 0 {
			return nil, fmt.Errorf(
				"database %s uses the old single-vault schema; move it aside or start with a fresh -db path", path)
		}
	}

	// Every row is scoped by vault_id — the opaque per-vault namespace the
	// client sends on each call. Separate people (or an unrelated vault on the
	// same device) get separate rev sequences, meta, and entries; the server
	// still only ever sees ciphertext + server-assigned revs.
	schema := `
CREATE TABLE IF NOT EXISTS revs (
  vault_id TEXT PRIMARY KEY,
  rev      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  vault_id   TEXT NOT NULL,
  id         TEXT NOT NULL,
  iv         BLOB,
  ciphertext BLOB,
  updated_at INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  rev        INTEGER NOT NULL,
  PRIMARY KEY (vault_id, id)
);
CREATE INDEX IF NOT EXISTS idx_entries_vault_rev ON entries(vault_id, rev);
CREATE TABLE IF NOT EXISTS meta (
  vault_id TEXT PRIMARY KEY,
  doc      TEXT NOT NULL,
  rev      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_auth (
  vault_id   TEXT PRIMARY KEY,
  token_hash BLOB NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &store{db: db}, nil
}

// nextRev bumps and returns a vault's private revision counter within a
// transaction. Each vault_id has its own monotonic sequence, so one person's
// writes never advance another's cursor.
func nextRev(tx *sql.Tx, vault string) (int64, error) {
	if _, err := tx.Exec(
		`INSERT INTO revs (vault_id, rev) VALUES (?, 1)
		 ON CONFLICT(vault_id) DO UPDATE SET rev = rev + 1`, vault); err != nil {
		return 0, err
	}
	var rev int64
	if err := tx.QueryRow(`SELECT rev FROM revs WHERE vault_id = ?`, vault).Scan(&rev); err != nil {
		return 0, err
	}
	return rev, nil
}

func (s *store) maxRev(vault string) (int64, error) {
	var rev int64
	err := s.db.QueryRow(`SELECT rev FROM revs WHERE vault_id = ?`, vault).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return rev, err
}

/* ==================== wire types ==================== */

type entryDTO struct {
	ID         string `json:"id"`
	IV         string `json:"iv"`         // base64, may be "" for tombstones
	Ciphertext string `json:"ciphertext"` // base64, may be "" for tombstones
	UpdatedAt  int64  `json:"updatedAt"`
	Deleted    bool   `json:"deleted"`
	Rev        int64  `json:"rev"`
}

type pushItem struct {
	entryDTO
	Base int64 `json:"base"` // rev this edit was derived from (0 = new)
}

func b64(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(bs)
}

func unb64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

/* ==================== main ==================== */

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	tlsAddr := flag.String("tlsaddr", ":8443", "HTTPS listen address (used when cert/key exist)")
	certFile := flag.String("cert", "certs/cert.pem", "TLS certificate file")
	keyFile := flag.String("key", "certs/key.pem", "TLS key file")
	dev := flag.Bool("dev", false, "serve web/ from disk instead of the embedded copy")
	dbPath := flag.String("db", "", "SQLite database path (default: ownvault.db next to the executable)")
	token := flag.String("token", os.Getenv("OWNVAULT_TOKEN"), "shared-secret bearer token required for sync (recommended when public); env OWNVAULT_TOKEN")
	plainHTTP := flag.Bool("plainhttp", false, "keep serving plain HTTP to non-localhost clients even when the TLS listener is up (e.g. HTTPS port firewalled, or TLS terminated elsewhere)")
	healthcheck := flag.Bool("healthcheck", false, "probe the running server's /healthz and exit; backs the container HEALTHCHECK")
	flag.Parse()

	// The image is distroless: no shell, no curl, nothing a CMD-SHELL probe
	// could run. So the container health check runs this same binary with
	// -healthcheck, which dials loopback on -addr and exits by the result.
	if *healthcheck {
		if err := nitrokit.HealthProbe(*addr); err != nil {
			log.Fatal(err)
		}
		return
	}

	// A short token invites online guessing that the rate limiter only slows.
	// Refuse at startup rather than warn: a warning in a Docker log is never
	// read, and the fix is one command (see README: openssl rand -hex 16).
	if *token != "" && len(*token) < minTokenLen {
		log.Fatalf("-token is %d characters; use at least %d (generate one with: openssl rand -hex 16)",
			len(*token), minTokenLen)
	}

	var webRoot fs.FS
	if *dev {
		webRoot = os.DirFS("web")
	} else {
		sub, err := fs.Sub(embedded, "web")
		if err != nil {
			log.Fatal(err)
		}
		webRoot = sub
	}

	if *dbPath == "" {
		*dbPath = defaultDBPath()
	}
	st, err := openStore(*dbPath)
	if err != nil {
		log.Fatalf("open db %s: %v", *dbPath, err)
	}
	log.Printf("vault database: %s", *dbPath)

	h := newHub()
	mux := http.NewServeMux()

	// Sync API. auth() enforces the token when one is configured, with a
	// shared per-client failure limiter across every endpoint.
	limiter := nitrokit.NewFailLimiter(authFailLimit, authFailWindow)
	// Deployed behind Nginx Proxy Manager, so a request's peer is the proxy on
	// a private Docker network. Trusting private peers is what keeps the
	// limiter bucketing by real client instead of collapsing every device into
	// one bucket; a public peer's forwarding headers are still ignored.
	trust := nitrokit.TrustPrivateProxies()
	mux.HandleFunc("/api/state", auth(*token, limiter, trust, st.handleState))
	mux.HandleFunc("/api/meta", auth(*token, limiter, trust, st.handleMeta(h)))
	mux.HandleFunc("/api/pull", auth(*token, limiter, trust, st.handlePull))
	mux.HandleFunc("/api/push", auth(*token, limiter, trust, st.handlePush(h)))
	mux.HandleFunc("/api/setupqr", auth(*token, limiter, trust, handleSetupQR))

	// Liveness only, and deliberately unauthenticated: it reports that the
	// process is serving, which anyone who can reach the port already knows.
	mux.HandleFunc("GET /healthz", nitrokit.Healthz)

	// Server-sent events: keepalive pings plus "changed" notifications when
	// another device writes. Deliberately unauthenticated even when a token is
	// set: it carries only pings and a bare "changed at rev N" (no ciphertext),
	// EventSource can't send auth headers, and the template's reachability code
	// relies on it. Acting on a notification (pulling) still requires the token.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		// ?vault=<id> scopes the "changed" notifications to one vault. The
		// reachability probe in app.js connects without it and just rides the
		// keepalive pings below. Checked before anything is written, so a
		// server at its cap can still answer with a real status.
		ch := h.add(strings.TrimSpace(r.URL.Query().Get("vault")))
		if ch == nil {
			http.Error(w, "too many connections", http.StatusServiceUnavailable)
			return
		}
		defer h.remove(ch)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		// nginx (e.g. Nginx Proxy Manager terminating TLS in front of this)
		// buffers proxied responses by default, which can hold SSE events back
		// from the client. This response header is nginx's documented opt-out,
		// honored per-response with no proxy config needed; other servers
		// ignore it.
		w.Header().Set("X-Accel-Buffering", "no")

		// http.ResponseController, NOT a w.(http.Flusher) assertion: this
		// handler runs inside nitrokit.WriteBudget, whose ResponseWriter
		// wrapper forwards flushing through Unwrap but does not itself
		// implement http.Flusher — the assertion would fail and every stream
		// would 500. The first flush doubles as the support probe and commits
		// the headers above, so the client sees the stream open immediately;
		// an unflushable writer reports ErrNotSupported without committing
		// anything, leaving the error path a clean 500.
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "retry: 3000\n\nevent: ping\ndata: {}\n\n")
		if err := rc.Flush(); err != nil {
			return
		}

		tick := time.NewTicker(25 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-h.done: // server draining
				return
			case msg := <-ch:
				if _, err := fmt.Fprintf(w, "event: changed\ndata: %s\n\n", msg); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
			case <-tick.C:
				if _, err := fmt.Fprintf(w, "event: ping\ndata: {}\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
			}
		}
	})

	files := http.FileServerFS(webRoot)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(webRoot, name); err == nil {
			// House rule: HTML always revalidates. The shell and every htmx
			// fragment name the asset URLs they load, so serving one stale is
			// exactly what strands a client on old CSS or JS. The file server
			// sends Last-Modified, so a revalidation costs a 304, not a
			// re-transfer. Assets keep the file server's own defaults.
			if strings.HasSuffix(name, ".html") {
				nitrokit.NoCache(w)
			}
			files.ServeHTTP(w, r)
			return
		}
		// Not a real file, so it is an app route (/settings, ...): serve the
		// shell and let the client load the matching fragment.
		nitrokit.NoCache(w)
		http.ServeFileFS(w, r, webRoot, "index.html")
	})

	// One chokepoint for the browser-side headers, wrapped in the write
	// budget that stands in for the zeroed WriteTimeout (see newVaultServer).
	handler := nitrokit.WriteBudget(sseWriteBudget,
		nitrokit.SecureHeaders(vaultCSP, vaultPermissions, mux))

	// Serve HTTPS as well when mkcert files are present — service workers
	// (and PWA install) require a secure context on anything but localhost.
	// The keypair is loaded here rather than by the listener so a broken cert
	// fails at startup with a clear message instead of on the first request.
	var servers []*http.Server
	tlsUp := false
	tlsPort := ""
	_, certErr := os.Stat(*certFile)
	_, keyErr := os.Stat(*keyFile)
	if certErr == nil && keyErr == nil {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("load TLS keypair: %v", err)
		}
		tlsUp = true
		if _, p, err := net.SplitHostPort(*tlsAddr); err == nil {
			tlsPort = p
		}
		// This listener terminates TLS itself, so it owns the HSTS policy.
		tlsSrv := newVaultServer(*tlsAddr, nitrokit.HSTS(handler))
		tlsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		servers = append(servers, tlsSrv)
		log.Printf("listening on https://localhost%s", *tlsAddr)
	}

	httpHandler := hstsWhenProxied(handler)
	if tlsUp && !*plainHTTP {
		// With TLS up, plain HTTP stays available only for loopback (desktop
		// dev, where HTTP is already a secure context). Everything else — e.g.
		// a phone typing the LAN IP — is redirected to the HTTPS listener so
		// the sync token and ciphertext never travel in the clear. -plainhttp
		// opts out for setups where the redirect would strand clients (HTTPS
		// port not published/firewalled, or TLS handled by a proxy).
		httpHandler = redirectToTLS(httpHandler, tlsPort)
	}
	servers = append(servers, newVaultServer(*addr, httpHandler))

	// Release the event streams the moment the drain starts. Each open
	// /events response is an in-flight request, so without this every restart
	// would wait out the full 10s shutdown budget. OnceFunc because both
	// listeners register the same closer.
	closeStreams := sync.OnceFunc(h.close)
	for _, srv := range servers {
		srv.RegisterOnShutdown(closeStreams)
	}

	log.Printf("listening on http://localhost%s (dev=%v, auth=%v)", *addr, *dev, *token != "")
	runErr := nitrokit.Run(context.Background(), servers...)
	// Close the database only after Run returns: handlers are still querying
	// it throughout the drain.
	if err := st.db.Close(); err != nil {
		log.Printf("close db: %v", err)
	}
	if runErr != nil {
		log.Fatal(runErr)
	}
	log.Print("shutdown complete")
}

// newVaultServer applies nitrokit's house timeouts, then the two overrides
// this workload needs.
func newVaultServer(addr string, h http.Handler) *http.Server {
	srv := nitrokit.NewServer(addr, h)
	// /events is an open-ended stream, and a whole-response write timeout
	// would cut it. nitrokit.WriteBudget restores per-write slow-client
	// protection in its place.
	srv.WriteTimeout = 0
	// The house 15s bounds the whole request body, and /api/push accepts up to
	// maxPushBytes for a full-vault restore — which 15s would need a ~4.5
	// Mbit/s uplink to finish. Two minutes lets a slow mobile link through
	// while still bounding how long a trickling connection holds a goroutine.
	srv.ReadTimeout = 2 * time.Minute
	return srv
}

// hstsWhenProxied sends HSTS on the plain-HTTP listener when a reverse proxy
// reports that it terminated TLS. nitrokit.HSTS covers the listener that
// terminates TLS itself; this covers the documented public deployment, where
// Nginx Proxy Manager terminates and r.TLS is nil here. Trusting the header is
// safe for HSTS specifically: a browser ignores the header when it arrives
// over an insecure connection, so spoofing it on plain HTTP achieves nothing.
func hstsWhenProxied(next http.Handler) http.Handler {
	secure := nitrokit.HSTS(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			secure.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// redirectToTLS sends non-loopback plain-HTTP requests to the HTTPS listener.
func redirectToTLS(next http.Handler, tlsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if isLoopbackHost(host) {
			next.ServeHTTP(w, r)
			return
		}
		u := "https://" + net.JoinHostPort(host, tlsPort) + r.URL.RequestURI()
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	})
}

// isLoopbackHost covers the whole loopback range (127.0.0.0/8, ::1), not just
// the literal 127.0.0.1 — addresses like 127.0.0.2 are common for running
// several local dev services and are just as local.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func defaultDBPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "ownvault.db"
	}
	return filepath.Join(filepath.Dir(exe), "ownvault.db")
}

/* ==================== auth ==================== */

// auth wraps a handler so it requires the bearer token when one is configured.
// With no token set (typical for localhost/LAN), it's a pass-through.
func auth(token string, limiter *nitrokit.FailLimiter, trust *nitrokit.ProxyTrust, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			ip := trust.ClientIP(r).String()
			// Refuse before comparing: an over-limit request must not learn
			// whether its guess was right, or the 429 would slow nothing.
			if limiter.Blocked(ip) {
				http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
				return
			}
			got := r.Header.Get("X-Vault-Token")
			if got == "" {
				if b := r.Header.Get("Authorization"); strings.HasPrefix(b, "Bearer ") {
					got = strings.TrimPrefix(b, "Bearer ")
				}
			}
			// Constant-time compare: the token is the only gate between the
			// internet and write access, so don't leak match length via timing.
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				limiter.Fail(ip)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			limiter.Pass(ip)
		}
		next(w, r)
	}
}

// vaultID reads the opaque per-vault namespace key the client sends on every
// sync call (X-Vault-Id). It scopes all storage so unrelated people can share
// one server without seeing each other's (already encrypted) data. It is not a
// secret and never decrypts anything — the shared token, if configured, is the
// access gate; the vault id only says which partition to read or write.
func vaultID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Vault-Id"))
}

// requireVault resolves the namespace for handlers that read or write vault
// data, rejecting a missing or absurd id. Writes it out and returns ok=false
// when invalid so the caller can just return.
func requireVault(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := vaultID(r)
	if v == "" || len(v) > 200 {
		http.Error(w, "missing or invalid vault id", http.StatusBadRequest)
		return "", false
	}
	return v, true
}

/* ==================== per-vault write auth ==================== */

// Per-vault write credential (X-Vault-Write): the client derives it from the
// vault key (SHA-256, one-way — it reveals nothing about the key), so every
// device that can unlock a vault automatically proves write rights, with no
// extra secret to copy around. Trust-on-first-use: the first write to a vault
// claims it by storing the credential's hash; every later write must present
// the same credential. This closes the shared-server gap where any co-tenant
// holding the server-wide -token could overwrite (never read) another
// tenant's ciphertext. Reads stay gated by the server token + the unguessable
// vault id: ciphertext is not secret, and a fresh device must be able to pull
// the wrapped-key record before it can unlock anything.
//
// Rotation (X-Vault-Write-New on /api/meta PUT): a full re-encrypt replaces
// the vault key, so the client proves the old credential and hands over the
// new one in the same meta write that installs the new wrapped-key record.
//
// The stored hash is SHA-256 of the (already high-entropy, 256-bit) header
// value, so a leaked server DB doesn't hand out write credentials.

func writeAuthToken(r *http.Request) string {
	t := r.Header.Get("X-Vault-Write")
	if len(t) > 200 {
		return ""
	}
	return t
}

// checkWriteAuth verifies (or first-use-claims) the vault's write credential
// inside the caller's transaction. newToken, when non-empty and the old
// credential verified, replaces the stored hash (rotation).
func checkWriteAuth(tx *sql.Tx, vault, token, newToken string) (bool, error) {
	if token == "" {
		return false, nil
	}
	sum := sha256.Sum256([]byte(token))
	var stored []byte
	err := tx.QueryRow(`SELECT token_hash FROM vault_auth WHERE vault_id = ?`, vault).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		if newToken != "" { // claim with the newer credential when rotating
			sum = sha256.Sum256([]byte(newToken))
		}
		_, err = tx.Exec(`INSERT INTO vault_auth (vault_id, token_hash) VALUES (?, ?)`, vault, sum[:])
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(stored, sum[:]) != 1 {
		return false, nil
	}
	if newToken != "" && len(newToken) <= 200 {
		rot := sha256.Sum256([]byte(newToken))
		if _, err := tx.Exec(
			`UPDATE vault_auth SET token_hash = ? WHERE vault_id = ?`, rot[:], vault); err != nil {
			return false, err
		}
	}
	return true, nil
}

// requireWriteAuth wraps checkWriteAuth with the HTTP error response.
func requireWriteAuth(w http.ResponseWriter, r *http.Request, tx *sql.Tx, vault string) bool {
	ok, err := checkWriteAuth(tx, vault, writeAuthToken(r), r.Header.Get("X-Vault-Write-New"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return false
	}
	if !ok {
		http.Error(w, "vault write credential missing or wrong", http.StatusForbidden)
		return false
	}
	return true
}

/* ==================== handlers ==================== */

// A light probe (reachability / auth check). Reports the caller's own vault
// only; with no vault id it just confirms the server is up and the token (if
// any) was accepted.
func (s *store) handleState(w http.ResponseWriter, r *http.Request) {
	v := vaultID(r)
	rev, err := s.maxRev(v)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var n int
	if v != "" {
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM meta WHERE vault_id = ?`, v).Scan(&n)
	}
	nitrokit.WriteJSON(w, http.StatusOK, map[string]any{"rev": rev, "hasMeta": n > 0})
}

// handleSetupQR renders the client-composed setup code as a QR PNG. The code
// holds only values this server already knows — the vault id (sent on every
// API call), its own token, its own URL — so rendering it here gives the
// server nothing new and spares the client a vendored JS QR encoder. POST
// body, never a query parameter: the code contains the token, and URLs end
// up in access logs. no-store for the same reason.
func handleSetupQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		body.Text == "" || len(body.Text) > 1024 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code, err := qr.Encode(body.Text, qr.M)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, private")
	_, _ = w.Write(code.PNG())
}

// GET returns the wrapped-key record (for a fresh device to bootstrap).
// PUT stores it (first device, or a master-password change re-wrap).
func (s *store) handleMeta(h *hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vault, ok := requireVault(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			var doc string
			var rev int64
			err := s.db.QueryRow(`SELECT doc, rev FROM meta WHERE vault_id = ?`, vault).Scan(&doc, &rev)
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "no meta", http.StatusNotFound)
				return
			}
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"doc":%s,"rev":%d}`, doc, rev)
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, maxMetaBytes)
			var body struct {
				Doc json.RawMessage `json:"doc"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Doc) == 0 {
				http.Error(w, "bad meta", http.StatusBadRequest)
				return
			}
			tx, err := s.db.Begin()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			defer tx.Rollback()
			if !requireWriteAuth(w, r, tx, vault) {
				return
			}
			rev, err := nextRev(tx, vault)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if _, err := tx.Exec(
				`INSERT INTO meta (vault_id, doc, rev) VALUES (?, ?, ?)
				 ON CONFLICT(vault_id) DO UPDATE SET doc = excluded.doc, rev = excluded.rev`,
				vault, string(body.Doc), rev); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := tx.Commit(); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			h.broadcast(vault, fmt.Sprintf(`{"rev":%d}`, rev))
			nitrokit.WriteJSON(w, http.StatusOK, map[string]any{"rev": rev})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// GET /api/pull?since=<rev>: everything with rev > since, plus meta if it
// changed past since, plus the current server rev (the client's new cursor).
func (s *store) handlePull(w http.ResponseWriter, r *http.Request) {
	vault, ok := requireVault(w, r)
	if !ok {
		return
	}
	var since int64
	fmt.Sscan(r.URL.Query().Get("since"), &since)

	rows, err := s.db.Query(
		`SELECT id, iv, ciphertext, updated_at, deleted, rev FROM entries WHERE vault_id = ? AND rev > ? ORDER BY rev`, vault, since)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	entries := []entryDTO{}
	for rows.Next() {
		var e entryDTO
		var iv, ct []byte
		var del int
		if err := rows.Scan(&e.ID, &iv, &ct, &e.UpdatedAt, &del, &e.Rev); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		e.IV, e.Ciphertext, e.Deleted = b64(iv), b64(ct), del != 0
		entries = append(entries, e)
	}

	resp := map[string]any{"entries": entries}

	var doc string
	var metaRev int64
	err = s.db.QueryRow(`SELECT doc, rev FROM meta WHERE vault_id = ?`, vault).Scan(&doc, &metaRev)
	if err == nil && metaRev > since {
		resp["meta"] = map[string]any{"doc": json.RawMessage(doc), "rev": metaRev}
	}

	rev, err := s.maxRev(vault)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp["rev"] = rev
	nitrokit.WriteJSON(w, http.StatusOK, resp)
}

// POST /api/push: apply the client's dirty entries with optimistic
// concurrency. Each item carries the base rev it derived from; if the server's
// current rev for that id still matches, accept and assign a new rev,
// otherwise report a conflict with the server's current version.
func (s *store) handlePush(h *hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vault, ok := requireVault(w, r)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPushBytes)
		var body struct {
			Entries []pushItem `json:"entries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad push", http.StatusBadRequest)
			return
		}

		type result struct {
			ID     string    `json:"id"`
			Status string    `json:"status"` // "ok" | "conflict"
			Rev    int64     `json:"rev,omitempty"`
			Server *entryDTO `json:"server,omitempty"`
		}
		results := make([]result, 0, len(body.Entries))
		changed := false

		tx, err := s.db.Begin()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer tx.Rollback()

		if !requireWriteAuth(w, r, tx, vault) {
			return
		}

		for _, it := range body.Entries {
			var curRev int64
			err := tx.QueryRow(`SELECT rev FROM entries WHERE vault_id = ? AND id = ?`, vault, it.ID).Scan(&curRev)
			if errors.Is(err, sql.ErrNoRows) {
				curRev = 0
			} else if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}

			if curRev != it.Base {
				// Divergence — return the server's current version.
				var e entryDTO
				var iv, ct []byte
				var del int
				if scanErr := tx.QueryRow(
					`SELECT id, iv, ciphertext, updated_at, deleted, rev FROM entries WHERE vault_id = ? AND id = ?`, vault, it.ID,
				).Scan(&e.ID, &iv, &ct, &e.UpdatedAt, &del, &e.Rev); scanErr == nil {
					e.IV, e.Ciphertext, e.Deleted = b64(iv), b64(ct), del != 0
					results = append(results, result{ID: it.ID, Status: "conflict", Server: &e})
				} else {
					results = append(results, result{ID: it.ID, Status: "conflict"})
				}
				continue
			}

			iv, err := unb64(it.IV)
			if err != nil {
				http.Error(w, "bad iv", http.StatusBadRequest)
				return
			}
			ct, err := unb64(it.Ciphertext)
			if err != nil {
				http.Error(w, "bad ciphertext", http.StatusBadRequest)
				return
			}
			newRev, err := nextRev(tx, vault)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			del := 0
			if it.Deleted {
				del = 1
			}
			if _, err := tx.Exec(
				`INSERT INTO entries (vault_id, id, iv, ciphertext, updated_at, deleted, rev)
				 VALUES (?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(vault_id, id) DO UPDATE SET
				   iv = excluded.iv, ciphertext = excluded.ciphertext,
				   updated_at = excluded.updated_at, deleted = excluded.deleted,
				   rev = excluded.rev`,
				vault, it.ID, iv, ct, it.UpdatedAt, del, newRev); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			results = append(results, result{ID: it.ID, Status: "ok", Rev: newRev})
			changed = true
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		rev, _ := s.maxRev(vault)
		if changed {
			h.broadcast(vault, fmt.Sprintf(`{"rev":%d}`, rev))
		}
		nitrokit.WriteJSON(w, http.StatusOK, map[string]any{"rev": rev, "results": results})
	}
}
