// A small server for the PWA App.
//
// Everything under web/ is embedded into the binary, so `go build` produces
// a single deployable file. Requests that match a real file are served as-is;
// any other path is an app route (/dashboard, /profile, ...) and gets the
// shell — the client then loads the matching fragment.
//
// During development run with -dev to serve web/ from disk, so edits show up
// on refresh without rebuilding.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed all:web
var embedded embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	tlsAddr := flag.String("tlsaddr", ":8443", "HTTPS listen address (used when cert/key exist)")
	certFile := flag.String("cert", "certs/cert.pem", "TLS certificate file")
	keyFile := flag.String("key", "certs/key.pem", "TLS key file")
	dev := flag.Bool("dev", false, "serve web/ from disk instead of the embedded copy")
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

	// Server-sent events. Today this only carries keepalive pings — the
	// client uses the connection state for true reachability. To push real
	// data later, write more named events here (or via a broadcast hub) and
	// add matching addEventListener calls in app.js.
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")

		// retry: how long the browser waits before auto-reconnecting
		fmt.Fprintf(w, "retry: 3000\n\nevent: ping\ndata: {}\n\n")
		fl.Flush()

		tick := time.NewTicker(25 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				if _, err := fmt.Fprintf(w, "event: ping\ndata: {}\n\n"); err != nil {
					return
				}
				fl.Flush()
			}
		}
	})

	files := http.FileServerFS(webRoot)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
				log.Fatal(http.ListenAndServeTLS(*tlsAddr, *certFile, *keyFile, nil))
			}()
		}
	}

	log.Printf("listening on http://localhost%s (dev=%v)", *addr, *dev)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
