package nitrokit

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACME configures automatic TLS certificates through the Automatic
// Certificate Management Environment (ACME) protocol — by default,
// Let's Encrypt.
type ACME struct {
	// Hosts is the hostnames to obtain certificates for. Handshakes for
	// any other name are refused, so a stranger pointing their DNS at
	// the server cannot make it request certificates.
	//
	// An entry may be a wildcard ("*.example.com"), which requires DNS
	// to be set: wildcards are only issued through the DNS-01 challenge.
	// A wildcard does not cover its apex — list "example.com" as its own
	// entry when both are served.
	Hosts []string

	// DNS places the TXT records that prove domain control for wildcard
	// entries. nitrokit ships Route53; implement DNSSolver for other
	// providers. Exact (non-wildcard) hosts never need it — they
	// validate over HTTP on port 80.
	DNS DNSSolver

	// CacheDir is the directory certificates and the account key persist
	// in across restarts. Required, and in Docker it must be a volume:
	// without persistence every restart requests fresh certificates, and
	// Let's Encrypt's rate limits turn a few redeploys into an outage.
	CacheDir string

	// Email is where the certificate authority sends expiry and problem
	// notices. Optional, but an unreachable operator finds out about a
	// renewal failure from the browser error instead.
	Email string
}

// acmeHTTPAddr is where the challenge-and-redirect server listens. The
// ACME HTTP-01 challenge is defined on port 80, so this is only variable
// for tests, which cannot bind 80.
var acmeHTTPAddr = ":80"

// RunTLS is Run for a server that terminates its own TLS instead of
// sitting behind a proxy. It obtains and renews certificates
// automatically, and serves until ctx is cancelled or the process
// receives SIGINT or SIGTERM, with the same bounded drain as Run.
//
// srv.Addr is normally ":443". RunTLS also starts a second server on
// port 80 that answers ACME challenges and redirects everything else to
// HTTPS; both servers come down together. The host must therefore be
// reachable from the internet on ports 80 and 443, and calling RunTLS
// accepts the certificate authority's terms of service on your behalf.
//
// Handlers served this way should also set Strict-Transport-Security —
// wrap them in HSTS.
// acmeDirectoryURL is the CA the wildcard path talks to. A variable only
// so tests can point it at a local fake; autocert has its own default.
var acmeDirectoryURL = acme.LetsEncryptURL

func RunTLS(ctx context.Context, srv *http.Server, a ACME) error {
	if len(a.Hosts) == 0 {
		return errors.New("nitrokit: ACME.Hosts is empty")
	}
	if a.CacheDir == "" {
		return errors.New("nitrokit: ACME.CacheDir is empty")
	}
	var exact, wildcards []string
	for _, h := range a.Hosts {
		switch {
		case strings.HasPrefix(h, "*.") && strings.Count(h, "*") == 1 && strings.Contains(h[2:], "."):
			wildcards = append(wildcards, h)
		case strings.Contains(h, "*"):
			return fmt.Errorf("nitrokit: invalid host %q: only a leading *.domain wildcard is supported", h)
		default:
			exact = append(exact, h)
		}
	}
	if len(wildcards) > 0 && a.DNS == nil {
		return errors.New("nitrokit: wildcard hosts need ACME.DNS, because wildcards are only issued through DNS-01")
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(exact...),
		Cache:      autocert.DirCache(a.CacheDir),
		Email:      a.Email,
	}
	// The manager's TLS config both fetches certificates on demand and
	// advertises the acme-tls/1 protocol, so the TLS-ALPN-01 challenge
	// works on 443 as well as HTTP-01 on 80.
	tcfg := m.TLSConfig()

	if len(wildcards) > 0 {
		// Renewal failures happen with no request attached, so they
		// surface the way http.Server reports its own errors.
		logf := log.Printf
		if srv.ErrorLog != nil {
			logf = srv.ErrorLog.Printf
		}
		var mgrs []*dnsCert
		for _, w := range wildcards {
			mgr := newDNSCert(w, a.DNS, a.CacheDir, a.Email, logf)
			mgr.directoryURL = acmeDirectoryURL
			mgrs = append(mgrs, mgr)
		}

		// Names under a wildcard serve from its manager; everything else
		// falls through to autocert.
		fallthroughGet := tcfg.GetCertificate
		tcfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			for _, mgr := range mgrs {
				if mgr.matches(hello.ServerName) {
					return mgr.certificate()
				}
			}
			return fallthroughGet(hello)
		}

		// The renew loops stop when serving stops.
		mctx, cancel := context.WithCancel(ctx)
		defer cancel()
		for _, mgr := range mgrs {
			go mgr.renewLoop(mctx)
		}
	}
	srv.TLSConfig = tcfg

	// Run derives each server's start from TLSConfig: srv now has one, the
	// redirect server never does.
	redirect := NewServer(acmeHTTPAddr, m.HTTPHandler(nil))
	return Run(ctx, srv, redirect)
}
