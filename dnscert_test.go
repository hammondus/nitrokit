// Internal tests: dnsCert is unexported, and the flow needs a fake ACME
// directory. The fake implements just enough of RFC 8555's happy path for
// x/crypto/acme to complete one DNS-01 order; it decodes JWS payloads
// without verifying signatures, because what is under test is this
// module's orchestration, not the CA protocol.
package nitrokit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeACME struct {
	t       *testing.T
	url     string // directory URL
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	leafTTL time.Duration

	mu         sync.Mutex
	orders     int
	authzValid bool
	leaf       []byte
	nonce      atomic.Int64
}

func newFakeACME(t *testing.T, leafTTL time.Duration) *fakeACME {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nitrokit test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeACME{t: t, caKey: caKey, caCert: caCert, leafTTL: leafTTL}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	f.url = srv.URL + "/dir"
	return f
}

func (f *fakeACME) orderCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orders
}

// jsonResp writes a JSON body with the Replay-Nonce every ACME response
// must carry.
func (f *fakeACME) jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%06d", f.nonce.Add(1)))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeACME) handler() http.Handler {
	mux := http.NewServeMux()
	base := func(r *http.Request) string { return "http://" + r.Host }

	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, r *http.Request) {
		f.jsonResp(w, 200, map[string]string{
			"newNonce":   base(r) + "/nonce",
			"newAccount": base(r) + "/acct",
			"newOrder":   base(r) + "/order",
			"revokeCert": base(r) + "/revoke",
			"keyChange":  base(r) + "/keychange",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%06d", f.nonce.Add(1)))
	})
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", base(r)+"/acct/1")
		f.jsonResp(w, 201, map[string]any{"status": "valid"})
	})
	mux.HandleFunc("POST /order", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.orders++
		f.authzValid = false
		f.mu.Unlock()
		w.Header().Set("Location", base(r)+"/order/1")
		f.jsonResp(w, 201, map[string]any{
			"status":         "pending",
			"finalize":       base(r) + "/finalize",
			"authorizations": []string{base(r) + "/authz/1"},
		})
	})
	mux.HandleFunc("POST /authz/1", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		status := "pending"
		if f.authzValid {
			status = "valid"
		}
		f.mu.Unlock()
		f.jsonResp(w, 200, map[string]any{
			"status":     status,
			"wildcard":   true,
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]string{{
				"type":   "dns-01",
				"url":    base(r) + "/chal/1",
				"token":  "test-token",
				"status": status,
			}},
		})
	})
	mux.HandleFunc("POST /chal/1", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authzValid = true
		f.mu.Unlock()
		f.jsonResp(w, 200, map[string]string{
			"type": "dns-01", "url": base(r) + "/chal/1",
			"token": "test-token", "status": "valid",
		})
	})
	mux.HandleFunc("POST /finalize", func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			f.t.Errorf("finalize: decode JWS: %v", err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
		if err != nil {
			f.t.Errorf("finalize: decode payload: %v", err)
		}
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			f.t.Errorf("finalize: unmarshal: %v", err)
		}
		csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
		if err != nil {
			f.t.Errorf("finalize: decode csr: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			f.t.Errorf("finalize: parse csr: %v", err)
			return
		}

		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(f.leafTTL),
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, f.caCert, csr.PublicKey, f.caKey)
		if err != nil {
			f.t.Errorf("finalize: sign: %v", err)
			return
		}
		f.mu.Lock()
		f.leaf = leafDER
		f.mu.Unlock()

		w.Header().Set("Location", base(r)+"/order/1")
		f.jsonResp(w, 200, map[string]any{
			"status":         "valid",
			"finalize":       base(r) + "/finalize",
			"certificate":    base(r) + "/cert/1",
			"authorizations": []string{base(r) + "/authz/1"},
		})
	})
	mux.HandleFunc("POST /order/1", func(w http.ResponseWriter, r *http.Request) {
		f.jsonResp(w, 200, map[string]any{
			"status":         "valid",
			"finalize":       base(r) + "/finalize",
			"certificate":    base(r) + "/cert/1",
			"authorizations": []string{base(r) + "/authz/1"},
		})
	})
	mux.HandleFunc("POST /cert/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%06d", f.nonce.Add(1)))
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		f.mu.Lock()
		leaf := f.leaf
		f.mu.Unlock()
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})
	})
	return mux
}

// fakeSolver records TXT operations.
type fakeSolver struct {
	mu       sync.Mutex
	sets     []string
	cleanups []string
}

func (s *fakeSolver) SetTXT(ctx context.Context, fqdn, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets = append(s.sets, fqdn+"="+value)
	return nil
}

func (s *fakeSolver) CleanupTXT(ctx context.Context, fqdn, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanups = append(s.cleanups, fqdn+"="+value)
	return nil
}

func newTestDNSCert(t *testing.T, fake *fakeACME, solver DNSSolver, dir string) *dnsCert {
	t.Helper()
	m := newDNSCert("*.example.com", solver, dir, "ops@example.com", t.Logf)
	m.directoryURL = fake.url
	return m
}

func TestDNSCertObtain(t *testing.T) {
	fake := newFakeACME(t, 90*24*time.Hour)
	solver := &fakeSolver{}
	dir := t.TempDir()
	m := newTestDNSCert(t, fake, solver, dir)

	if _, err := m.certificate(); err == nil {
		t.Error("certificate() before obtain returned a certificate")
	}
	if err := m.ensure(t.Context()); err != nil {
		t.Fatal(err)
	}

	cert, err := m.certificate()
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != "*.example.com" {
		t.Errorf("leaf DNSNames = %v, want [*.example.com]", got)
	}
	if err := cert.Leaf.CheckSignatureFrom(fake.caCert); err != nil {
		t.Errorf("leaf not signed by the test CA: %v", err)
	}

	solver.mu.Lock()
	defer solver.mu.Unlock()
	if len(solver.sets) != 1 || len(solver.cleanups) != 1 {
		t.Fatalf("solver calls: sets=%v cleanups=%v, want one each", solver.sets, solver.cleanups)
	}
	if want := "_acme-challenge.example.com="; len(solver.sets[0]) <= len(want) || solver.sets[0][:len(want)] != want {
		t.Errorf("SetTXT = %q, want %s<record>", solver.sets[0], want)
	}
	if solver.sets[0] != solver.cleanups[0] {
		t.Errorf("cleanup %q does not match set %q", solver.cleanups[0], solver.sets[0])
	}

	// The account key uses autocert's cache entry, so both cert paths
	// share one CA account.
	if _, err := os.Stat(filepath.Join(dir, "acme_account+key")); err != nil {
		t.Errorf("account key not persisted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "_wildcard.example.com.pem")); err != nil {
		t.Errorf("certificate not persisted: %v", err)
	}
}

// TestDNSCertReload pins restart behaviour: a second manager over the
// same cache dir serves the stored certificate without touching the CA.
func TestDNSCertReload(t *testing.T) {
	fake := newFakeACME(t, 90*24*time.Hour)
	dir := t.TempDir()
	m := newTestDNSCert(t, fake, &fakeSolver{}, dir)
	if err := m.ensure(t.Context()); err != nil {
		t.Fatal(err)
	}

	m2 := newDNSCert("*.example.com", &fakeSolver{}, dir, "", t.Logf)
	m2.directoryURL = "http://127.0.0.1:0/unreachable" // any CA call would fail loudly
	cert, err := m2.certificate()
	if err != nil {
		t.Fatalf("certificate after reload: %v", err)
	}
	if cert.Leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("reloaded leaf DNSNames = %v", cert.Leaf.DNSNames)
	}
	if err := m2.ensure(t.Context()); err != nil {
		t.Errorf("ensure with a fresh cached certificate should not call the CA: %v", err)
	}
}

// TestDNSCertRenews pins the renewal decision: a certificate inside the
// 30-day window triggers a fresh order.
func TestDNSCertRenews(t *testing.T) {
	fake := newFakeACME(t, 10*24*time.Hour) // issued already inside the window
	m := newTestDNSCert(t, fake, &fakeSolver{}, t.TempDir())

	if err := m.ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := fake.orderCount(); got != 1 {
		t.Fatalf("orders after first ensure = %d", got)
	}
	if err := m.ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := fake.orderCount(); got != 2 {
		t.Errorf("orders after second ensure = %d, want 2 (certificate is inside the renewal window)", got)
	}
}

func TestDNSCertMatches(t *testing.T) {
	m := newDNSCert("*.example.com", nil, t.TempDir(), "", t.Logf)
	tests := []struct {
		name string
		want bool
	}{
		{"foo.example.com", true},
		{"FOO.example.com", true},
		{"foo.example.com.", true},
		{"example.com", false},
		{"a.b.example.com", false},
		{"fooexample.com", false},
		{"foo.example.org", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := m.matches(tt.name); got != tt.want {
			t.Errorf("matches(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
