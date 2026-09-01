// Internal tests: RunTLS's challenge server is pinned to port 80, which
// tests cannot bind, so they override the unexported listen address.
package nitrokit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

func TestRunTLSValidation(t *testing.T) {
	srv := NewServer(":443", nil)
	if err := RunTLS(t.Context(), srv, ACME{CacheDir: t.TempDir()}); err == nil {
		t.Error("empty Hosts accepted")
	}
	if err := RunTLS(t.Context(), srv, ACME{Hosts: []string{"example.com"}}); err == nil {
		t.Error("empty CacheDir accepted")
	}
	if err := RunTLS(t.Context(), srv, ACME{Hosts: []string{"*.example.com"}, CacheDir: t.TempDir()}); err == nil {
		t.Error("wildcard host without a DNSSolver accepted")
	}
	for _, h := range []string{"foo.*.com", "*example.com", "*.com", "*.*.example.com"} {
		if err := RunTLS(t.Context(), srv, ACME{Hosts: []string{h}, CacheDir: t.TempDir(), DNS: &fakeSolver{}}); err == nil {
			t.Errorf("invalid host %q accepted", h)
		}
	}
}

// TestRunTLSWildcardEndToEnd drives the whole wildcard path: RunTLS
// obtains a certificate from the fake CA through the fake solver, and a
// real TLS handshake for a name under the wildcard verifies against it.
func TestRunTLSWildcardEndToEnd(t *testing.T) {
	fake := newFakeACME(t, 90*24*time.Hour)
	acmeDirectoryURL = fake.url
	defer func() { acmeDirectoryURL = acme.LetsEncryptURL }()
	acmeHTTPAddr = freePort(t)
	defer func() { acmeHTTPAddr = ":80" }()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr := freePort(t)
	srv := NewServer(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	done := make(chan error, 1)
	go func() {
		done <- RunTLS(ctx, srv, ACME{
			Hosts:    []string{"*.example.com"},
			CacheDir: t.TempDir(),
			DNS:      &fakeSolver{},
		})
	}()
	waitPort(t, addr)

	// Issuance runs in the background; handshakes fail until the renew
	// loop has obtained the certificate.
	pool := x509.NewCertPool()
	pool.AddCert(fake.caCert)
	cfg := &tls.Config{ServerName: "foo.example.com", RootCAs: pool}
	var conn *tls.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err = tls.Dial("tcp", addr, cfg); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("no verified handshake within 10s: %v", err)
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("served certificate covers %v, want [*.example.com]", leaf.DNSNames)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunTLS = %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunTLS did not return within 5s of cancel")
	}
}

// TestRunTLSLifecycle starts the pair, checks the port-80 side redirects
// to HTTPS but leaves the ACME challenge path alone, and checks a cancel
// brings both down cleanly.
func TestRunTLSLifecycle(t *testing.T) {
	acmeHTTPAddr = freePort(t)
	defer func() { acmeHTTPAddr = ":80" }()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	srv := NewServer(freePort(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	done := make(chan error, 1)
	go func() {
		done <- RunTLS(ctx, srv, ACME{Hosts: []string{"example.com"}, CacheDir: t.TempDir()})
	}()
	waitPort(t, acmeHTTPAddr)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+acmeHTTPAddr+"/some/page", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("plain HTTP request: status %d, want 302", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "https://example.com/some/page"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	// The challenge path must be answered on port 80, never redirected,
	// or certificate issuance breaks.
	req, err = http.NewRequestWithContext(ctx, "GET", "http://"+acmeHTTPAddr+"/.well-known/acme-challenge/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Error("ACME challenge path was redirected to HTTPS")
	}

	// Drop the client's pooled connections before stopping. The transport
	// can dial a spare connection that never carries a request; the
	// server holds such a connection in StateNew, and Shutdown reaps
	// never-used connections only after 5 seconds — correct behaviour,
	// but it would make this assertion time-dependent.
	client.CloseIdleConnections()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunTLS = %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunTLS did not return within 5s of cancel")
	}

	// Read after RunTLS has returned: the write happens on its goroutine.
	if srv.TLSConfig == nil {
		t.Error("RunTLS did not install a TLS config")
	}
}

// TestRunTLSListenError pins that a dead TLS listener takes the port-80
// server down with it instead of leaving it orphaned.
func TestRunTLSListenError(t *testing.T) {
	acmeHTTPAddr = freePort(t)
	defer func() { acmeHTTPAddr = ":80" }()

	// Occupy the TLS port so ListenAndServeTLS fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := NewServer(ln.Addr().String(), nil)
	done := make(chan error, 1)
	go func() {
		done <- RunTLS(t.Context(), srv, ACME{Hosts: []string{"example.com"}, CacheDir: t.TempDir()})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunTLS = nil, want address-in-use error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunTLS did not return within 5s of a failed listen")
	}

	// The redirect listener must be gone once RunTLS has returned.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", acmeHTTPAddr)
		if err != nil {
			return // refused: it is down
		}
		conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("port-80 server still listening after RunTLS returned")
}

func TestRunAllPrefersServeError(t *testing.T) {
	// A listener failure and the resulting shutdown both produce errors;
	// the listener's is the cause and must win.
	boom := errors.New("boom")
	s1 := &http.Server{}
	s2 := &http.Server{}
	// Stub a healthy second server without a socket: serve blocks until
	// runAll shuts it down, like a real listener would.
	stopped := make(chan struct{})
	s2.RegisterOnShutdown(func() { close(stopped) })
	err := runAll(t.Context(),
		serverEntry{s1, func() error { return boom }},
		serverEntry{s2, func() error {
			<-stopped
			return http.ErrServerClosed
		}},
	)
	if !errors.Is(err, boom) {
		t.Fatalf("runAll = %v, want boom", err)
	}
}
