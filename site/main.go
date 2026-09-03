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
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hammondus/mailer"
	"github.com/hammondus/nitrokit"
)

// all: on templates is load-bearing, not decoration. A plain //go:embed
// directive skips files whose names start with "_" or ".", and nitrokit's
// template convention names partials with a leading underscore — so without
// it _partials.html is missing from the binary and every page renders as a
// 500 in production while dev, which reads the same files from disk, is fine.
//
//go:embed web all:templates
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

// siteCSP forbids script entirely — the site has none — so an injection has
// nothing to execute. It is passed to nitrokit.SecureHeaders explicitly
// because it is *stricter* than nitrokit.DefaultCSP, which allows
// script-src 'self'; taking the default here would loosen the strongest
// header on the page. The Permissions-Policy default is taken as-is: a site
// with no JavaScript needs none of the features it turns off.
const siteCSP = "default-src 'self'; script-src 'none'; style-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'none'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"

var (
	dev     = flag.Bool("dev", false, "serve web/ and templates/ from disk and re-parse per request")
	addr    = flag.String("addr", ":8090", "HTTP listen address")
	baseURL = flag.String("baseurl", "", "public origin, e.g. https://ownvault.app (used for canonical and og: tags)")
	repoURL = flag.String("repo", "https://github.com/hammondus/ownvault", "GitHub repository URL")
	demoURL = flag.String("demo", os.Getenv("OWNVAULT_SITE_DEMO_URL"), "public URL of the demo vault server; blank hides every link to it (env OWNVAULT_SITE_DEMO_URL)")
	contact = flag.String("to", os.Getenv("OWNVAULT_SITE_CONTACT_TO"), "destination address for contact form mail (env OWNVAULT_SITE_CONTACT_TO)")
	// Which peers may set X-Forwarded-For. The old -proxy boolean trusted the
	// header from anyone, which made the per-IP submission limit bypassable by
	// sending a different value each time. Naming the proxy instead means an
	// untrusted peer's header is ignored outright.
	trustedProxies = flag.String("trusted-proxies", "private",
		`peers whose X-Forwarded-For is trusted: "private" for all loopback and private space, a comma-separated list of CIDRs or addresses, or empty to trust none`)
	healthcheck = flag.Bool("healthcheck", false, "probe the running server's /healthz and exit; backs the container HEALTHCHECK")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	// The image is distroless: no shell, no curl, nothing a CMD-SHELL probe
	// could run. So the container health check runs this same binary with
	// -healthcheck, which dials loopback on -addr and exits by the result.
	if *healthcheck {
		if err := nitrokit.HealthProbe(*addr); err != nil {
			log.Fatal(err)
		}
		return
	}

	// A schemeless -demo value becomes a RELATIVE href in the template, so the
	// demo buttons would quietly point at a path on this site. Refuse at
	// startup rather than warn: a warning in a container log is never read.
	if *demoURL != "" && !strings.HasPrefix(*demoURL, "http://") && !strings.HasPrefix(*demoURL, "https://") {
		log.Fatalf("-demo must include the scheme, e.g. https://%s", *demoURL)
	}

	s, err := newServer()
	if err != nil {
		log.Fatalf("startup: %v", err)
	}

	srv := nitrokit.NewServer(*addr, s.routes())
	// Deliberately longer than nitrokit's house values: the contact handler
	// talks SMTP synchronously, so a response can legitimately take as long as
	// the upstream mail server does.
	srv.ReadHeaderTimeout = 10 * time.Second
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 60 * time.Second
	srv.IdleTimeout = 2 * time.Minute

	log.Printf("site listening on %s (dev=%v, mail=%s)", *addr, *dev, s.mailMode)
	if err := nitrokit.Run(context.Background(), srv); err != nil {
		log.Fatal(err)
	}
	log.Print("shutdown complete")
}

// ---------- server ----------

// assetServer is the shape both nitrokit asset types share: nitrokit.Assets
// hashes an embedded tree once at startup, nitrokit.DirAssets re-hashes a
// directory when a file changes. The site needs the first in production and
// the second in -dev, and nothing else in the file cares which it has.
type assetServer interface {
	http.Handler
	URL(name string) string
}

type server struct {
	assets assetServer // serves web/ and stamps its cache-busting URLs

	// tplMu guards tpl, which is swapped on every request in dev mode.
	tplMu sync.RWMutex
	tpl   *nitrokit.Templates

	sender   mailer.Sender
	mailMode string // "smtp" or "log", for the startup line
	to       string

	// formKey signs the timestamp embedded in each rendered form. It is
	// generated per process: a restart invalidating open forms is a fair
	// trade for never needing a secret in configuration.
	formKey []byte

	limiter *ipLimiter

	// trust decides whose X-Forwarded-For is believed when resolving the
	// client address the submission limit buckets by.
	trust *nitrokit.ProxyTrust
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

	trust, err := parseTrust(*trustedProxies)
	if err != nil {
		return nil, err
	}
	s.trust = trust

	// Assets mount at the root, so style.css keeps its /style.css?v=<hash>
	// URL. In dev they come from disk and are re-hashed when a file changes,
	// which is what makes an edit show on refresh with the hashing intact; in
	// production they are embedded and hashed once, because they cannot change
	// under a running process.
	if *dev {
		s.assets, err = nitrokit.NewDirAssets("web", "/")
	} else {
		var sub fs.FS
		if sub, err = fs.Sub(embedded, "web"); err == nil {
			s.assets, err = nitrokit.NewAssets(sub, "/")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}

	if err := s.parseTemplates(); err != nil {
		return nil, err
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

// parseTrust turns the -trusted-proxies flag into a trust list. "private" is
// the deployed shape (Nginx Proxy Manager on a private Docker network); a
// CIDR list is tighter; empty trusts nobody, for a server exposed directly.
func parseTrust(list string) (*nitrokit.ProxyTrust, error) {
	if list == "private" {
		return nitrokit.TrustPrivateProxies(), nil
	}
	return nitrokit.ParseTrustedProxies(list)
}

// sourceFS picks disk in dev mode so template edits show on refresh, and the
// embedded copy otherwise. The two have identical layouts, so nothing else
// branches. Assets do not go through it — they have their own dev/embedded
// split in newServer.
func sourceFS() fs.FS {
	if *dev {
		return os.DirFS(".")
	}
	return embedded
}

func (s *server) parseTemplates() error {
	sub, err := fs.Sub(sourceFS(), "templates")
	if err != nil {
		return err
	}
	// The asset func is looked up through s on every call rather than bound
	// once, so it keeps working across the per-request re-parse in dev.
	t, err := nitrokit.ParseTemplates(sub, template.FuncMap{
		"asset": func(name string) string { return s.assets.URL(name) },
	})
	if err != nil {
		return err
	}
	s.tplMu.Lock()
	s.tpl = t
	s.tplMu.Unlock()
	return nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /contact", s.handleContactForm)
	mux.HandleFunc("POST /contact", s.handleContactPost)
	mux.HandleFunc("GET /healthz", nitrokit.Healthz)
	// The asset server owns everything else: a request carrying a ?v= hash
	// names its exact bytes and is cached forever, anything else gets an hour,
	// and an unknown path 404s.
	mux.Handle("GET /", s.assets)
	return nitrokit.SecureHeaders(siteCSP, "", mux)
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
	// DemoURL is empty unless -demo is set, and every link to the demo is
	// wrapped in {{if .DemoURL}}. A site without a demo server must not offer
	// one, and the real hostname stays out of the repository.
	DemoURL string

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

// render writes one page with an explicit status. The status is a parameter
// rather than something the caller writes first, because a failed contact
// submission re-renders the same page as a 400 or a 429 — and writing the
// header before rendering committed the response, so every header the render
// set afterwards (Content-Type, Cache-Control) was silently dropped on those
// error pages.
//
// nitrokit.Render buffers, so a template that fails halfway is a clean 500
// rather than a 200 with half a page, and it adds the ETag that makes the
// no-cache policy cost a 304 instead of a full re-render on every navigation.
func (s *server) render(w http.ResponseWriter, r *http.Request, name string, status int, p page) {
	if *dev {
		if err := s.parseTemplates(); err != nil {
			log.Printf("template: %v", err)
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
	}
	p.RepoURL = *repoURL
	p.DemoURL = *demoURL
	if *baseURL != "" && p.Canon == "" {
		p.Canon = strings.TrimRight(*baseURL, "/") + r.URL.Path
	}

	s.tplMu.RLock()
	t := s.tpl
	s.tplMu.RUnlock()

	if err := t.Render(w, r, name, status, p); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "index.html", http.StatusOK, page{
		Title: "Own Vault — a password manager you actually own",
		Desc:  "A zero-knowledge password manager. Encrypted in your browser, synced by a server that cannot read it, and yours to host.",
		Nav:   "home",
	})
}

func (s *server) handleContactForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "contact.html", http.StatusOK, page{
		Title:   "Contact — Own Vault",
		Desc:    "Get in touch about Own Vault.",
		Nav:     "contact",
		Token:   s.newToken(time.Now()),
		MailOff: s.to == "",
	})
}

func (s *server) handleContactPost(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, msg string, f contactForm) {
		s.render(w, r, "contact.html", status, page{
			Title: "Contact — Own Vault", Desc: "Get in touch about Own Vault.",
			Nav: "contact", Token: s.newToken(time.Now()),
			Error: msg, Form: f, MailOff: s.to == "",
		})
	}

	// ReadForm caps the body and dispatches on the Content-Type, so a form
	// that ever grows a file input keeps working — r.ParseForm alone ignores a
	// multipart body and hands the handler five empty fields. It writes its
	// own 413 or 400, which is the right answer for a 64 KiB submission: no
	// person types that, so there is no one to show a friendly page to.
	if !nitrokit.ReadForm(w, r, maxFormBytes) {
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
		log.Printf("contact: honeypot tripped from %s", s.clientIP(r))
		s.render(w, r, "contact.html", http.StatusOK, page{Title: "Contact — Own Vault", Nav: "contact", Sent: true})
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

	if !s.limiter.allow(s.clientIP(r)) {
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
		Text:    composeBody(f, s.clientIP(r)),
	}
	if err := s.sender.Send(ctx, msg); err != nil {
		log.Printf("contact: send failed: %v", err)
		fail(http.StatusBadGateway, "The message could not be sent just now. Please try again shortly, or open a GitHub issue.", f)
		return
	}

	log.Printf("contact: sent from %q via %s", f.Email, s.clientIP(r))
	s.render(w, r, "contact.html", http.StatusOK, page{
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

// clientIP returns the address to rate-limit and to log.
//
// It walks X-Forwarded-For from the RIGHT and stops at the first hop that is
// not a trusted proxy. The old code took the leftmost value whenever -proxy
// was on, which is the value an attacker writes: a spam run could send a
// different X-Forwarded-For with every request and never spend more than one
// of its three hourly submissions. The rightmost hops are the ones a proxy
// appended itself, and a peer that is not in the trust list has its header
// ignored entirely.
func (s *server) clientIP(r *http.Request) string {
	return s.trust.ClientIP(r).String()
}
