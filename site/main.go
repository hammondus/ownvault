// Command site serves the Own Vault website: a landing page and a contact
// form. It is deliberately separate from the vault server in main.go at the
// repository root — that binary is the zero-knowledge sync point and has no
// business carrying an SMTP client, a template set, or public marketing copy.
//
// The site has no JavaScript at all. The contact form is a plain HTML POST,
// which keeps the whole thing auditable and lets the Content-Security-Policy
// forbid script outright.
//
//	go run . -dev                 # serve web/ and templates/ from disk
//	go build -o ovsite . && ./ovsite -addr :8090
//
// Mail is configured by environment (see .env.example); with no SMTP host set,
// the server logs the composed message instead of sending it, so the whole
// path still runs in development.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hammondus/mailer"
)

//go:embed web templates
var embedded embed.FS

const (
	// maxFormBytes caps a contact submission. The form is five short fields;
	// anything larger is either a mistake or an attempt to fill memory.
	maxFormBytes = 64 << 10

	// minFillSeconds is how long a human takes to fill the form, at the very
	// fastest. A submission faster than this is automation.
	minFillSeconds = 3

	// maxFormAge expires a rendered form. It bounds how long a scraped token
	// stays usable, and a form left open for hours is stale anyway.
	maxFormAge = 2 * time.Hour

	// Per-IP submission limit. Generous for a person with something to say,
	// useless for a spam run.
	rateWindow = time.Hour
	rateBurst  = 3
)

var (
	dev      = flag.Bool("dev", false, "serve web/ and templates/ from disk and re-parse per request")
	addr     = flag.String("addr", ":8090", "HTTP listen address")
	baseURL  = flag.String("baseurl", "", "public origin, e.g. https://ownvault.app (used for canonical and og: tags)")
	repoURL  = flag.String("repo", "https://github.com/hammondus/ownvault", "GitHub repository URL")
	contact  = flag.String("to", os.Getenv("OWNVAULT_SITE_CONTACT_TO"), "destination address for contact form mail (env OWNVAULT_SITE_CONTACT_TO)")
	behindLB = flag.Bool("proxy", true, "trust X-Forwarded-For from the reverse proxy for client IP")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	s, err := newServer()
	if err != nil {
		log.Fatalf("startup: %v", err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		log.Printf("site listening on %s (dev=%v, mail=%s)", *addr, *dev, s.mailMode)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// ---------- server ----------

type server struct {
	files fs.FS // the web/ subtree, however it is being read

	// tplMu guards tpl, which is swapped on every request in dev mode.
	tplMu sync.RWMutex
	tpl   *template.Template

	sender   mailer.Sender
	mailMode string // "smtp" or "log", for the startup line
	to       string

	// formKey signs the timestamp embedded in each rendered form. It is
	// generated per process: a restart invalidating open forms is a fair
	// trade for never needing a secret in configuration.
	formKey []byte

	limiter *ipLimiter

	// assetV maps a path under web/ to a short hash of its contents. Per file,
	// not one version for the whole site: a shared stamp would leave an edited
	// image cached for a year whenever the CSS happened not to change.
	// Empty in dev, where files are read from disk and no-cache does the work.
	assetV map[string]string
}

func newServer() (*server, error) {
	s := &server{
		formKey: make([]byte, 32),
		limiter: newIPLimiter(rateBurst, rateWindow),
		to:      strings.TrimSpace(*contact),
	}
	if _, err := rand.Read(s.formKey); err != nil {
		return nil, fmt.Errorf("form key: %w", err)
	}

	sub, err := fs.Sub(sourceFS(), "web")
	if err != nil {
		return nil, err
	}
	s.files = sub

	if err := s.parseTemplates(); err != nil {
		return nil, err
	}

	// In dev the files are read from disk per request, so hashes stamped at
	// startup would be wrong the moment one is edited; skip them there and let
	// no-cache do the work. In production the files are embedded and cannot
	// change under a running process, so hashing once is correct.
	if !*dev {
		if err := s.hashAssets(); err != nil {
			return nil, fmt.Errorf("hash assets: %w", err)
		}
	}

	cfg := mailer.ConfigFromEnv("OWNVAULT_SITE_SMTP_")
	cfg.Timeout = 20 * time.Second
	cfg.RateLimit = 1 // one message per second is far above what a contact form needs
	switch {
	case s.to == "":
		// No destination is a configuration mistake in production, but it must
		// not stop the site serving its pages. Fail the form, not the process.
		log.Print("WARNING: no contact address set (-to / OWNVAULT_SITE_CONTACT_TO); the contact form will refuse to send")
		s.sender, s.mailMode = mailer.NewLog(nil), "log (no destination)"
	case cfg.Configured():
		s.sender, s.mailMode = mailer.NewSMTP(cfg), "smtp "+cfg.Host
	default:
		s.sender, s.mailMode = mailer.NewLog(nil), "log (SMTP not configured)"
	}
	return s, nil
}

// sourceFS picks disk in dev mode so edits show on refresh, and the embedded
// copy otherwise. The two have identical layouts, so nothing else branches.
func sourceFS() fs.FS {
	if *dev {
		return os.DirFS(".")
	}
	return embedded
}

func (s *server) parseTemplates() error {
	t, err := template.New("").Funcs(template.FuncMap{
		"asset": s.asset,
	}).ParseFS(sourceFS(), "templates/*.html")
	if err != nil {
		return err
	}
	s.tplMu.Lock()
	s.tpl = t
	s.tplMu.Unlock()
	return nil
}

// hashAssets records a short content hash for every file under web/.
func (s *server) hashAssets() error {
	s.assetV = make(map[string]string)
	return fs.WalkDir(s.files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(s.files, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		s.assetV[p] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
}

// asset returns a URL for a static file, content-hashed in production so it can
// be cached forever and still change when the bytes do.
func (s *server) asset(name string) string {
	if v := s.assetV[name]; v != "" {
		return "/" + name + "?v=" + v
	}
	return "/" + name
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /contact", s.handleContactForm)
	mux.HandleFunc("POST /contact", s.handleContactPost)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "ok\n")
	})
	mux.Handle("GET /", s.static())
	return securityHeaders(mux)
}

// static serves web/ with cache headers set per resource: a request carrying a
// ?v= hash names its exact bytes and can be cached forever; everything else
// gets an hour, because that URL's content can change under a client.
func (s *server) static() http.Handler {
	fileServer := http.FileServer(http.FS(s.files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// securityHeaders applies one policy to every response. The CSP forbids script
// entirely — the site has none — so an injection has nothing to execute.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'none'; style-src 'self'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'none'; " +
		"form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ---------- pages ----------

// page is everything a template needs. Fields specific to the contact page are
// zero on the landing page and simply go unused.
type page struct {
	Title   string
	Desc    string
	Nav     string // which nav link is current
	Canon   string // absolute URL, empty when -baseurl is unset
	RepoURL string

	// Contact page state.
	Token   string
	Sent    bool
	Error   string
	Form    contactForm
	MailOff bool
}

type contactForm struct {
	Name    string
	Email   string
	Subject string
	Message string
}

func (s *server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	if *dev {
		if err := s.parseTemplates(); err != nil {
			log.Printf("template: %v", err)
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
	}
	p.RepoURL = *repoURL
	if *baseURL != "" && p.Canon == "" {
		p.Canon = strings.TrimRight(*baseURL, "/") + r.URL.Path
	}

	s.tplMu.RLock()
	t := s.tpl
	s.tplMu.RUnlock()

	// Render to memory first: a template that fails halfway must not leave a
	// 200 with half a page on the wire.
	var buf strings.Builder
	if err := t.ExecuteTemplate(&buf, name, p); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// HTML carries the URLs of every asset it references, so serving it stale
	// would defeat the content hashing above. Store, but always revalidate.
	w.Header().Set("Cache-Control", "no-cache")
	io.WriteString(w, buf.String())
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "index.html", page{
		Title: "Own Vault — a password manager you actually own",
		Desc:  "A zero-knowledge password manager. Encrypted in your browser, synced by a server that cannot read it, and yours to host.",
		Nav:   "home",
	})
}

func (s *server) handleContactForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "contact.html", page{
		Title:   "Contact — Own Vault",
		Desc:    "Get in touch about Own Vault.",
		Nav:     "contact",
		Token:   s.newToken(time.Now()),
		MailOff: s.to == "",
	})
}

func (s *server) handleContactPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)

	fail := func(status int, msg string, f contactForm) {
		w.WriteHeader(status)
		s.render(w, r, "contact.html", page{
			Title: "Contact — Own Vault", Desc: "Get in touch about Own Vault.",
			Nav: "contact", Token: s.newToken(time.Now()),
			Error: msg, Form: f, MailOff: s.to == "",
		})
	}

	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "That message was too large to accept.", contactForm{})
		return
	}

	f := contactForm{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		Email:   strings.TrimSpace(r.PostFormValue("email")),
		Subject: strings.TrimSpace(r.PostFormValue("subject")),
		Message: strings.TrimSpace(r.PostFormValue("message")),
	}

	// Honeypot: a field hidden from people, irresistible to form-filling bots.
	// Answer 200 with the success page so the bot learns nothing.
	if r.PostFormValue("website") != "" {
		log.Printf("contact: honeypot tripped from %s", clientIP(r))
		s.render(w, r, "contact.html", page{Title: "Contact — Own Vault", Nav: "contact", Sent: true})
		return
	}

	// Distinguish the two token failures a person can actually hit: an
	// expired form is worth explaining, whereas "too fast" only happens to
	// automation and needs no help.
	switch err := s.checkToken(r.PostFormValue("t"), time.Now()); {
	case errors.Is(err, errFormTooFast):
		fail(http.StatusBadRequest, "That was submitted faster than a person can type. Here is a fresh form.", f)
		return
	case err != nil:
		fail(http.StatusBadRequest, "That form had been open too long and expired. Here is a fresh one — please send it again.", f)
		return
	}

	if err := validate(f); err != nil {
		fail(http.StatusBadRequest, err.Error(), f)
		return
	}

	if s.to == "" {
		fail(http.StatusServiceUnavailable, "Mail is not configured on this server, so the form cannot send. Please open a GitHub issue instead.", f)
		return
	}

	if !s.limiter.allow(clientIP(r)) {
		fail(http.StatusTooManyRequests, "You have sent several messages already. Please wait an hour before sending another.", f)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// The sender is our own verified address, never the visitor's: sending as
	// an address on someone else's domain fails SPF and burns the domain's
	// reputation. Reply-To is what makes a reply go to the right place.
	msg := &mailer.Message{
		To:      []string{s.to},
		ReplyTo: f.Email,
		Subject: "[ownvault] " + f.Subject,
		Text:    composeBody(f, clientIP(r)),
	}
	if err := s.sender.Send(ctx, msg); err != nil {
		log.Printf("contact: send failed: %v", err)
		fail(http.StatusBadGateway, "The message could not be sent just now. Please try again shortly, or open a GitHub issue.", f)
		return
	}

	log.Printf("contact: sent from %q via %s", f.Email, clientIP(r))
	s.render(w, r, "contact.html", page{
		Title: "Message sent — Own Vault", Desc: "Get in touch about Own Vault.",
		Nav: "contact", Sent: true,
	})
}

func composeBody(f contactForm, ip string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From:    %s <%s>\n", f.Name, f.Email)
	fmt.Fprintf(&b, "Subject: %s\n", f.Subject)
	fmt.Fprintf(&b, "IP:      %s\n", ip)
	fmt.Fprintf(&b, "At:      %s\n\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString(f.Message)
	b.WriteString("\n")
	return b.String()
}

func validate(f contactForm) error {
	switch {
	case f.Name == "":
		return errors.New("Please give a name to reply to.")
	case len(f.Name) > 100:
		return errors.New("That name is too long.")
	case f.Email == "":
		return errors.New("Please give an email address, or the reply has nowhere to go.")
	case len(f.Email) > 254:
		return errors.New("That email address is too long.")
	case f.Subject == "":
		return errors.New("Please give the message a subject.")
	case len(f.Subject) > 150:
		return errors.New("That subject is too long.")
	case f.Message == "":
		return errors.New("The message is empty.")
	case len(f.Message) > 8000:
		return errors.New("That message is longer than this form accepts. Please open a GitHub issue instead.")
	}
	// mailer rejects header injection itself, but catching a malformed address
	// here turns a send error into a usable message on the form.
	if _, err := mail.ParseAddress(f.Email); err != nil {
		return errors.New("That does not look like an email address.")
	}
	if strings.ContainsAny(f.Subject, "\r\n") || strings.ContainsAny(f.Name, "\r\n") {
		return errors.New("Please remove the line breaks from the name and subject.")
	}
	return nil
}

// ---------- form token ----------

// errFormTooFast marks the one token failure worth its own message on the
// page: a submission that arrived quicker than a person could type it.
var errFormTooFast = errors.New("submitted too fast")

// newToken stamps the render time and signs it. Signing is what stops a bot
// minting its own timestamp: without the key it cannot claim the form was
// rendered three seconds ago.
func (s *server) newToken(now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	m := hmac.New(sha256.New, s.formKey)
	m.Write([]byte(ts))
	return ts + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *server) checkToken(tok string, now time.Time) error {
	ts, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return errors.New("malformed token")
	}
	m := hmac.New(sha256.New, s.formKey)
	m.Write([]byte(ts))
	want := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return errors.New("bad signature")
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	age := now.Sub(time.Unix(n, 0))
	if age < minFillSeconds*time.Second {
		return errFormTooFast
	}
	if age > maxFormAge {
		return errors.New("expired")
	}
	return nil
}

// ---------- per-IP rate limit ----------

// ipLimiter allows burst submissions per window per IP. It is a sliding log
// rather than a token bucket because the counts are tiny and the exact
// semantics ("three in the last hour") are then obvious from the code.
type ipLimiter struct {
	mu     sync.Mutex
	seen   map[string][]time.Time
	burst  int
	window time.Duration
}

func newIPLimiter(burst int, window time.Duration) *ipLimiter {
	return &ipLimiter{seen: make(map[string][]time.Time), burst: burst, window: window}
}

func (l *ipLimiter) allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Prune every key, not just this one: without it the map grows for the
	// life of the process, one entry per IP that ever submitted.
	for k, ts := range l.seen {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(l.seen, k)
		} else {
			l.seen[k] = kept
		}
	}

	if len(l.seen[ip]) >= l.burst {
		return false
	}
	l.seen[ip] = append(l.seen[ip], now)
	return true
}

// clientIP returns the address to rate-limit and to log. Behind a reverse
// proxy every RemoteAddr is the proxy, so the leftmost X-Forwarded-For entry
// is used instead — trustworthy only because -proxy asserts that a proxy we
// control sets that header.
func clientIP(r *http.Request) string {
	if *behindLB {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
