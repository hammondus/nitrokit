package nitrokit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hammondus/nitrokit"
)

// freeAddr reserves a loopback port and releases it for the server under
// test. Another process can take the port in the gap, but ListenAndServe
// offers no way to inject a listener, so this race is the cost of testing
// Run end to end.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitReady blocks until addr accepts a connection.
func waitReady(t *testing.T, addr string) {
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
	t.Fatalf("server on %s never became reachable", addr)
}

func TestNewServerTimeouts(t *testing.T) {
	srv := nitrokit.NewServer(":0", nil)
	if got, want := srv.ReadHeaderTimeout, 5*time.Second; got != want {
		t.Errorf("ReadHeaderTimeout = %v, want %v", got, want)
	}
	if got, want := srv.ReadTimeout, 15*time.Second; got != want {
		t.Errorf("ReadTimeout = %v, want %v", got, want)
	}
	if got, want := srv.WriteTimeout, 30*time.Second; got != want {
		t.Errorf("WriteTimeout = %v, want %v", got, want)
	}
	if got, want := srv.IdleTimeout, 60*time.Second; got != want {
		t.Errorf("IdleTimeout = %v, want %v", got, want)
	}
}

func TestRunServesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr := freeAddr(t)
	srv := nitrokit.NewServer(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))

	done := make(chan error, 1)
	go func() { done <- nitrokit.Run(ctx, srv) }()
	waitReady(t, addr)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel")
	}
}

func TestRunNoServers(t *testing.T) {
	if err := nitrokit.Run(t.Context()); err == nil {
		t.Fatal("Run with no servers = nil, want error")
	}
}

// selfSigned mints a loopback certificate so the TLS path is testable
// without touching the network or a CA.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// TestRunPlainAndTLSPair pins the multi-server rule: a server with a
// TLSConfig serves TLS from that config's certificates, its sibling
// serves plain HTTP, and one cancel drains both.
func TestRunPlainAndTLSPair(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	plainAddr, tlsAddr := freeAddr(t), freeAddr(t)
	plain := nitrokit.NewServer(plainAddr, handler)
	tlsSrv := nitrokit.NewServer(tlsAddr, handler)
	cert := selfSigned(t)
	tlsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	done := make(chan error, 1)
	go func() { done <- nitrokit.Run(ctx, plain, tlsSrv) }()
	waitReady(t, plainAddr)
	waitReady(t, tlsAddr)

	resp, err := http.Get("http://" + plainAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	resp, err = client.Get("https://" + tlsAddr + "/")
	if err != nil {
		t.Fatalf("TLS request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("TLS body = %q, err %v", body, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel")
	}
}

func TestRunListenError(t *testing.T) {
	// Occupy a port so ListenAndServe fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := nitrokit.NewServer(ln.Addr().String(), nil)
	done := make(chan error, 1)
	go func() { done <- nitrokit.Run(t.Context(), srv) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run = nil, want address-in-use error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of a failed listen")
	}
}

// TestRunDrainsInFlight holds a request open across the stop signal and
// checks that the drain lets it finish and that Run still returns nil.
func TestRunDrainsInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr := freeAddr(t)
	inHandler := make(chan struct{})
	release := make(chan struct{})
	srv := nitrokit.NewServer(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(inHandler)
		<-release
		io.WriteString(w, "drained")
	}))

	done := make(chan error, 1)
	go func() { done <- nitrokit.Run(ctx, srv) }()
	waitReady(t, addr)

	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			got <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		got <- result{body: string(b), err: err}
	}()

	<-inHandler
	cancel()
	// Let Shutdown close the listener first, so the request completes
	// during the drain rather than before it.
	time.Sleep(50 * time.Millisecond)
	close(release)

	r := <-got
	if r.err != nil {
		t.Fatalf("request during drain: %v", r.err)
	}
	if r.body != "drained" {
		t.Fatalf("body = %q, want %q", r.body, "drained")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of the drain finishing")
	}
}
