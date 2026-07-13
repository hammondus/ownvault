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
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed all:web
var embedded embed.FS

/* ==================== SSE broadcast hub ==================== */

// Fans "changed" notifications out to every connected client so other devices
// re-pull promptly. Keepalive pings share the same stream.
type hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

func newHub() *hub { return &hub{clients: make(map[chan string]struct{})} }

func (h *hub) add() chan string {
	ch := make(chan string, 8)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
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

func (h *hub) broadcast(msg string) {
	h.mu.Lock()
	for ch := range h.clients {
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
	schema := `
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
INSERT OR IGNORE INTO kv (k, v) VALUES ('rev', 0);
CREATE TABLE IF NOT EXISTS entries (
  id         TEXT PRIMARY KEY,
  iv         BLOB,
  ciphertext BLOB,
  updated_at INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  rev        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_rev ON entries(rev);
CREATE TABLE IF NOT EXISTS meta (
  id  INTEGER PRIMARY KEY CHECK (id = 1),
  doc TEXT NOT NULL,
  rev INTEGER NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &store{db: db}, nil
}

// nextRev bumps and returns the global revision counter within a transaction.
func nextRev(tx *sql.Tx) (int64, error) {
	if _, err := tx.Exec(`UPDATE kv SET v = v + 1 WHERE k = 'rev'`); err != nil {
		return 0, err
	}
	var rev int64
	if err := tx.QueryRow(`SELECT v FROM kv WHERE k = 'rev'`).Scan(&rev); err != nil {
		return 0, err
	}
	return rev, nil
}

func (s *store) maxRev() (int64, error) {
	var rev int64
	err := s.db.QueryRow(`SELECT v FROM kv WHERE k = 'rev'`).Scan(&rev)
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
	flag.Parse()

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

	// Sync API. auth() enforces the token when one is configured.
	mux.HandleFunc("/api/state", auth(*token, st.handleState))
	mux.HandleFunc("/api/meta", auth(*token, st.handleMeta(h)))
	mux.HandleFunc("/api/pull", auth(*token, st.handlePull))
	mux.HandleFunc("/api/push", auth(*token, st.handlePush(h)))

	// Server-sent events: keepalive pings plus "changed" notifications when
	// another device writes. Deliberately unauthenticated even when a token is
	// set: it carries only pings and a bare "changed at rev N" (no ciphertext),
	// EventSource can't send auth headers, and the template's reachability code
	// relies on it. Acting on a notification (pulling) still requires the token.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")

		ch := h.add()
		defer h.remove(ch)

		fmt.Fprintf(w, "retry: 3000\n\nevent: ping\ndata: {}\n\n")
		fl.Flush()

		tick := time.NewTicker(25 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case msg := <-ch:
				if _, err := fmt.Fprintf(w, "event: changed\ndata: %s\n\n", msg); err != nil {
					return
				}
				fl.Flush()
			case <-tick.C:
				if _, err := fmt.Fprintf(w, "event: ping\ndata: {}\n\n"); err != nil {
					return
				}
				fl.Flush()
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
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFileFS(w, r, webRoot, "index.html")
	})

	// Serve HTTPS as well when mkcert files are present — service workers
	// (and PWA install) require a secure context on anything but localhost.
	if _, err := os.Stat(*certFile); err == nil {
		if _, err := os.Stat(*keyFile); err == nil {
			go func() {
				log.Printf("listening on https://localhost%s", *tlsAddr)
				log.Fatal(http.ListenAndServeTLS(*tlsAddr, *certFile, *keyFile, mux))
			}()
		}
	}

	log.Printf("listening on http://localhost%s (dev=%v, auth=%v)", *addr, *dev, *token != "")
	log.Fatal(http.ListenAndServe(*addr, mux))
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
func auth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			got := r.Header.Get("X-Vault-Token")
			if got == "" {
				if b := r.Header.Get("Authorization"); strings.HasPrefix(b, "Bearer ") {
					got = strings.TrimPrefix(b, "Bearer ")
				}
			}
			if got != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

/* ==================== handlers ==================== */

func (s *store) handleState(w http.ResponseWriter, r *http.Request) {
	rev, err := s.maxRev()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var hasMeta bool
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM meta`).Scan(&n)
	hasMeta = n > 0
	writeJSON(w, map[string]any{"rev": rev, "hasMeta": hasMeta})
}

// GET returns the wrapped-key record (for a fresh device to bootstrap).
// PUT stores it (first device, or a master-password change re-wrap).
func (s *store) handleMeta(h *hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			var doc string
			var rev int64
			err := s.db.QueryRow(`SELECT doc, rev FROM meta WHERE id = 1`).Scan(&doc, &rev)
			if err == sql.ErrNoRows {
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
			rev, err := nextRev(tx)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if _, err := tx.Exec(
				`INSERT INTO meta (id, doc, rev) VALUES (1, ?, ?)
				 ON CONFLICT(id) DO UPDATE SET doc = excluded.doc, rev = excluded.rev`,
				string(body.Doc), rev); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := tx.Commit(); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			h.broadcast(fmt.Sprintf(`{"rev":%d}`, rev))
			writeJSON(w, map[string]any{"rev": rev})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// GET /api/pull?since=<rev>: everything with rev > since, plus meta if it
// changed past since, plus the current server rev (the client's new cursor).
func (s *store) handlePull(w http.ResponseWriter, r *http.Request) {
	var since int64
	fmt.Sscan(r.URL.Query().Get("since"), &since)

	rows, err := s.db.Query(
		`SELECT id, iv, ciphertext, updated_at, deleted, rev FROM entries WHERE rev > ? ORDER BY rev`, since)
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
	err = s.db.QueryRow(`SELECT doc, rev FROM meta WHERE id = 1`).Scan(&doc, &metaRev)
	if err == nil && metaRev > since {
		resp["meta"] = map[string]any{"doc": json.RawMessage(doc), "rev": metaRev}
	}

	rev, err := s.maxRev()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	resp["rev"] = rev
	writeJSON(w, resp)
}

// POST /api/push: apply the client's dirty entries with optimistic
// concurrency. Each item carries the base rev it derived from; if the server's
// current rev for that id still matches, accept and assign a new rev,
// otherwise report a conflict with the server's current version.
func (s *store) handlePush(h *hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		for _, it := range body.Entries {
			var curRev int64
			err := tx.QueryRow(`SELECT rev FROM entries WHERE id = ?`, it.ID).Scan(&curRev)
			if err == sql.ErrNoRows {
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
					`SELECT id, iv, ciphertext, updated_at, deleted, rev FROM entries WHERE id = ?`, it.ID,
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
			newRev, err := nextRev(tx)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			del := 0
			if it.Deleted {
				del = 1
			}
			if _, err := tx.Exec(
				`INSERT INTO entries (id, iv, ciphertext, updated_at, deleted, rev)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(id) DO UPDATE SET
				   iv = excluded.iv, ciphertext = excluded.ciphertext,
				   updated_at = excluded.updated_at, deleted = excluded.deleted,
				   rev = excluded.rev`,
				it.ID, iv, ct, it.UpdatedAt, del, newRev); err != nil {
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

		rev, _ := s.maxRev()
		if changed {
			h.broadcast(fmt.Sprintf(`{"rev":%d}`, rev))
		}
		writeJSON(w, map[string]any{"rev": rev, "results": results})
	}
}
