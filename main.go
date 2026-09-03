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
	"cmp"
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
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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

// Demo mode (-demo) turns this binary into a public sandbox that anyone may
// write to without a token. A private server trusts whoever holds the token,
// so it leaves these quantities to its owner; a demo server trusts nobody and
// has to bound every one of them. See DESIGN-DECISIONS.md "The demo server".
const (
	demoTTL        = 7 * 24 * time.Hour // a vault is deleted this long after its first write
	demoTTLDays    = int(demoTTL / (24 * time.Hour))
	demoSweepEvery = time.Hour      // how often the sweeper looks for expired vaults
	demoMaxEntries = 100            // live entries per vault
	demoMaxBytes   = 1 << 20        // stored ciphertext per vault, tombstones included
	demoMaxVaults  = 2000           // live vaults on the whole server
	demoIPVaults   = 10             // new vaults one client address may create...
	demoIPWindow   = 24 * time.Hour // ...within this window
)

//go:embed all:web
var embedded embed.FS

// The one place the app's version lives. `make version-patch` (or -minor /
// -major) rewrites this file; the Go binary embeds it, /js/version.js hands
// the same string to the browser, and the service worker keys its cache on it.
// Nothing else stores a version, so nothing can drift out of step.
//
//go:embed VERSION
var versionRaw string

// cmp.Or covers a VERSION file that is empty or whitespace: the app still
// runs, and an obviously wrong version is easier to diagnose than a blank one.
var appVersion = cmp.Or(strings.TrimSpace(versionRaw), "0.0.0-unknown")

// The SSE frame announcing this build, built once at startup. A deploy
// restarts the server, which drops every open stream; each client's automatic
// reconnect then delivers this. That is the whole push mechanism — no polling,
// and no version endpoint for a client to hammer.
var versionEvent = buildVersionEvent()

func buildVersionEvent() string {
	b, err := json.Marshal(map[string]string{"version": appVersion})
	if err != nil {
		// Unreachable for a map[string]string, but a silent empty frame here
		// would be a confusing way to find that out.
		log.Fatalf("encoding version event: %v", err)
	}
	return "event: version\ndata: " + string(b) + "\n\n"
}

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
	// demo is nil on a normal server, and that nil is what switches off every
	// demo-only limit below. A demo server is the only one that hands out
	// write access to strangers, so it is the only one that needs them.
	demo *demoGate
}

// demoGate holds the state the demo limits need beyond the database: the
// per-address creation log, and the proxy trust that turns a request into the
// address to charge it to.
type demoGate struct {
	ips   *ipQuota
	trust *nitrokit.ProxyTrust
}

// allowNewVault reports whether this request may bring a new vault into
// existence, and why not when it may not. The global cap is checked first so
// a full server does not also spend the caller's daily allowance.
func (g *demoGate) allowNewVault(tx *sql.Tx, r *http.Request) (string, bool) {
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM vault_auth`).Scan(&live); err != nil {
		return "cannot count demo vaults right now, try again later", false
	}
	if live >= demoMaxVaults {
		return fmt.Sprintf(
			"the demo server is full; demo vaults are deleted %d days after they are created, so try again later",
			demoTTLDays), false
	}
	if !g.ips.allow(g.trust.ClientIP(r).String()) {
		return "too many demo vaults created from your address today; try again tomorrow", false
	}
	return "", true
}

// ipQuota allows a burst of events per window per address. A sliding log
// rather than a token bucket because the counts are tiny and the semantics
// ("ten in the last day") are then plain from the code. The same shape as the
// website's contact-form limiter; that lives in the separate site module, so
// this is a deliberate copy rather than a shared dependency.
type ipQuota struct {
	mu     sync.Mutex
	seen   map[string][]time.Time
	burst  int
	window time.Duration
}

func newIPQuota(burst int, window time.Duration) *ipQuota {
	return &ipQuota{seen: make(map[string][]time.Time), burst: burst, window: window}
}

func (q *ipQuota) allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-q.window)

	q.mu.Lock()
	defer q.mu.Unlock()

	// Prune every key, not only this one: otherwise the map grows for the life
	// of the process, one entry per address that ever created a vault.
	for k, ts := range q.seen {
		kept := slices.DeleteFunc(ts, func(t time.Time) bool { return !t.After(cutoff) })
		if len(kept) == 0 {
			delete(q.seen, k)
		} else {
			q.seen[k] = kept
		}
	}

	if len(q.seen[ip]) >= q.burst {
		return false
	}
	q.seen[ip] = append(q.seen[ip], now)
	return true
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
  token_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL DEFAULT 0
);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	// created_at arrived with the demo server's 7-day sweep. CREATE TABLE IF
	// NOT EXISTS never alters a table that already exists, so add the column
	// to older databases here. Ask the table what it has rather than matching
	// the driver's error text, which is not part of any contract. The change
	// is additive: a server that never reads the column is unaffected.
	var hasCreatedAt int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('vault_auth') WHERE name = 'created_at'`).Scan(&hasCreatedAt); err != nil {
		return nil, err
	}
	if hasCreatedAt == 0 {
		if _, err := db.Exec(`ALTER TABLE vault_auth ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`); err != nil {
			return nil, err
		}
		// Backfill to now. The real claim times are unrecoverable, and dating
		// every existing vault to the epoch would tell a sweeper they all
		// expired long ago.
		if _, err := db.Exec(`UPDATE vault_auth SET created_at = ?`, time.Now().Unix()); err != nil {
			return nil, err
		}
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

// sweepDemo deletes every vault whose first write is older than demoTTL. It
// runs only on a demo server (see main), and reads vault_auth.created_at —
// the one clock reading in the schema the server assigns itself. Sorting by
// entries.updated_at instead would let a device with a wrong (or deliberately
// wrong) clock keep a vault alive forever.
//
// One transaction per vault rather than one big DELETE ... IN (...): the
// server holds a single writer connection, and a sweep of a full server would
// otherwise block sync behind it.
func (s *store) sweepDemo() {
	cutoff := time.Now().Add(-demoTTL).Unix()

	rows, err := s.db.Query(`SELECT vault_id FROM vault_auth WHERE created_at < ?`, cutoff)
	if err != nil {
		log.Printf("demo sweep: %v", err)
		return
	}
	var expired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			break
		}
		expired = append(expired, id)
	}
	rows.Close()

	swept := 0
	for _, id := range expired {
		if err := s.deleteVault(id); err != nil {
			log.Printf("demo sweep: delete vault: %v", err)
			continue
		}
		swept++
	}
	if swept > 0 {
		log.Printf("demo sweep: deleted %d vault(s) older than %d days", swept, demoTTLDays)
	}
}

// deleteVault removes every trace of one vault in a single transaction, so a
// crash mid-sweep leaves the vault whole and the next sweep deletes it. A
// partial delete is the state to avoid: an id stripped of its vault_auth row
// but still holding entries is unclaimed, and the next writer would take it
// over along with the leftover ciphertext.
func (s *store) deleteVault(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM entries WHERE vault_id = ?`,
		`DELETE FROM meta WHERE vault_id = ?`,
		`DELETE FROM revs WHERE vault_id = ?`,
		`DELETE FROM vault_auth WHERE vault_id = ?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	demo := flag.Bool("demo", false, "run as a public demo server: anyone may create a vault, vaults are capped and deleted 7 days after creation")
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

	// Deployed behind Nginx Proxy Manager, so a request's peer is the proxy on
	// a private Docker network. Trusting private peers is what keeps per-client
	// bucketing working instead of collapsing every device into one bucket; a
	// public peer's forwarding headers are still ignored.
	trust := nitrokit.TrustPrivateProxies()

	// Demo mode. The gate being non-nil is what arms every limit, including
	// the sweeper that deletes vaults — so a server started without -demo can
	// never run a destructive sweep, whatever else is misconfigured.
	if *demo {
		st.demo = &demoGate{ips: newIPQuota(demoIPVaults, demoIPWindow), trust: trust}
		log.Printf("DEMO MODE: open to anyone; vaults capped at %d entries / %d KB, %d per server, %d per address per day, deleted after %d days",
			demoMaxEntries, demoMaxBytes>>10, demoMaxVaults, demoIPVaults, demoTTLDays)
		// Sweep at startup as well as hourly, so a restart cannot postpone
		// expiry indefinitely on a server that is redeployed often.
		go func() {
			st.sweepDemo()
			for range time.Tick(demoSweepEvery) {
				st.sweepDemo()
			}
		}()
	}

	h := newHub()
	mux := http.NewServeMux()

	// Sync API. auth() enforces the token when one is configured, with a
	// shared per-client failure limiter across every endpoint.
	limiter := nitrokit.NewFailLimiter(authFailLimit, authFailWindow)
	mux.HandleFunc("/api/state", auth(*token, limiter, trust, st.handleState))
	mux.HandleFunc("/api/meta", auth(*token, limiter, trust, st.handleMeta(h)))
	mux.HandleFunc("/api/pull", auth(*token, limiter, trust, st.handlePull))
	mux.HandleFunc("/api/push", auth(*token, limiter, trust, st.handlePush(h)))
	mux.HandleFunc("/api/setupqr", auth(*token, limiter, trust, handleSetupQR))

	// Liveness only, and deliberately unauthenticated: it reports that the
	// process is serving, which anyone who can reach the port already knows.
	mux.HandleFunc("GET /healthz", nitrokit.Healthz)

	// The running build, as a script rather than an inline <script> or a
	// templated shell: the CSP forbids inline scripts, and generating this
	// from the embedded VERSION keeps it impossible for a checked-in copy to
	// go stale. no-cache so a client that reloads always learns the truth —
	// the service worker's cache key is derived from this value, so a stale
	// one would pin the whole app to an old cache.
	mux.HandleFunc("GET /js/version.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		nitrokit.NoCache(w)
		fmt.Fprintf(w, "window.APP_VERSION = %q;\n", appVersion)
		// Demo mode reaches the client the same way: from the server, never
		// from localStorage. A stored flag would ride a browser profile into
		// somebody's real vault; this one cannot outlive the origin serving
		// it. The value is the retention in days, so the banner's wording and
		// the sweeper read one constant.
		if *demo {
			fmt.Fprintf(w, "window.APP_DEMO = %d;\n", demoTTLDays)
		}
	})

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
		// Sent to every subscriber, vault-scoped or not: which build is
		// serving is a property of the server, not of a vault. The client
		// compares it with its own window.APP_VERSION and offers a reload.
		io.WriteString(w, versionEvent)
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
		_, err = tx.Exec(
			`INSERT INTO vault_auth (vault_id, token_hash, created_at) VALUES (?, ?, ?)`,
			vault, sum[:], time.Now().Unix())
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

// requireWriteAuth wraps checkWriteAuth with the HTTP error response, and on
// a demo server applies the limits that gate bringing a NEW vault into
// existence. There is no create endpoint — a vault exists from the moment the
// TOFU claim below inserts its row — so the claim is the only place those
// limits can live.
func (s *store) requireWriteAuth(w http.ResponseWriter, r *http.Request, tx *sql.Tx, vault string) bool {
	if s.demo != nil {
		var claimed int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM vault_auth WHERE vault_id = ?`, vault).Scan(&claimed); err != nil {
			http.Error(w, err.Error(), 500)
			return false
		}
		if claimed == 0 {
			if msg, ok := s.demo.allowNewVault(tx, r); !ok {
				http.Error(w, msg, http.StatusTooManyRequests)
				return false
			}
		}
	}
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
			if !s.requireWriteAuth(w, r, tx, vault) {
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

	// On a demo server, tell the client when this vault gets deleted. Sent on
	// every pull rather than as its own endpoint: the banner is only shown
	// inside the unlocked app, which is already pulling.
	if s.demo != nil {
		var created int64
		if err := s.db.QueryRow(
			`SELECT created_at FROM vault_auth WHERE vault_id = ?`, vault).Scan(&created); err == nil && created > 0 {
			resp["demoExpires"] = created + int64(demoTTL.Seconds())
		}
	}
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

		if !s.requireWriteAuth(w, r, tx, vault) {
			return
		}

		// Demo caps. Read once, then tracked across the batch, so a push
		// cannot step over the ceiling one item at a time. Only live entries
		// count towards the entry limit — that is the number the user sees in
		// the app — while the byte limit sums every stored row, tombstones
		// included, because that is what occupies the disk.
		var liveEntries, usedBytes int64
		if s.demo != nil {
			if err := tx.QueryRow(
				`SELECT COALESCE(SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END), 0),
				        COALESCE(SUM(LENGTH(ciphertext)), 0)
				 FROM entries WHERE vault_id = ?`, vault).Scan(&liveEntries, &usedBytes); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}

		for _, it := range body.Entries {
			var curRev, curLen int64
			var curDel int
			curLive := false
			err := tx.QueryRow(
				`SELECT rev, COALESCE(LENGTH(ciphertext), 0), deleted FROM entries WHERE vault_id = ? AND id = ?`,
				vault, it.ID).Scan(&curRev, &curLen, &curDel)
			if errors.Is(err, sql.ErrNoRows) {
				curRev = 0
			} else if err != nil {
				http.Error(w, err.Error(), 500)
				return
			} else {
				curLive = curDel == 0
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
			// Over a cap the whole push fails: the client keeps the entry
			// dirty and shows the reason, which is the honest outcome — the
			// user has to delete something before this vault accepts more.
			// 507 rather than 403, which already means "write credential
			// refused" to the client.
			if s.demo != nil {
				nextBytes := usedBytes - curLen + int64(len(ct))
				nextLive := liveEntries
				switch {
				case !it.Deleted && !curLive:
					nextLive++
				case it.Deleted && curLive:
					nextLive--
				}
				if nextLive > demoMaxEntries {
					http.Error(w, fmt.Sprintf("demo vaults hold at most %d entries; delete one and try again", demoMaxEntries),
						http.StatusInsufficientStorage)
					return
				}
				if nextBytes > demoMaxBytes {
					http.Error(w, fmt.Sprintf("demo vaults hold at most %d KB of encrypted data; delete an entry and try again", demoMaxBytes>>10),
						http.StatusInsufficientStorage)
					return
				}
				usedBytes, liveEntries = nextBytes, nextLive
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
