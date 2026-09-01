// Internal tests: the solver's endpoint and credentials are unexported.
package nitrokit

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRoute53 records the requests the solver makes and scripts the
// GetChange status sequence.
type fakeRoute53 struct {
	mu       sync.Mutex
	changes  []route53Change
	statuses []string // consumed by successive GetChange calls
	auths    []string
}

func (f *fakeRoute53) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /2013-04-01/hostedzone/{zone}/rrset/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ch route53Change
		if err := xml.Unmarshal(body, &ch); err != nil {
			t.Errorf("unmarshal change: %v", err)
		}
		f.mu.Lock()
		f.changes = append(f.changes, ch)
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		io.WriteString(w, `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C123</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`)
	})
	mux.HandleFunc("GET /2013-04-01/change/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		status := "INSYNC"
		if len(f.statuses) > 0 {
			status, f.statuses = f.statuses[0], f.statuses[1:]
		}
		f.mu.Unlock()
		io.WriteString(w, `<GetChangeResponse><ChangeInfo><Id>/change/`+r.PathValue("id")+`</Id><Status>`+status+`</Status></ChangeInfo></GetChangeResponse>`)
	})
	return mux
}

func newTestRoute53(t *testing.T, f *fakeRoute53) *Route53 {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return &Route53{
		zoneID:    "ZTEST",
		accessKey: "AKID",
		secretKey: "secret",
		endpoint:  srv.URL,
		client:    srv.Client(),
	}
}

func TestNewRoute53RequiresCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	if _, err := NewRoute53("ZTEST"); err == nil {
		t.Error("missing credentials accepted")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	if _, err := NewRoute53(""); err == nil {
		t.Error("empty zone ID accepted")
	}
	if _, err := NewRoute53("ZTEST"); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestRoute53SetTXT(t *testing.T) {
	f := &fakeRoute53{}
	r := newTestRoute53(t, f)

	if err := r.SetTXT(t.Context(), "_acme-challenge.example.com", "tok-value"); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.changes) != 1 {
		t.Fatalf("%d change calls, want 1", len(f.changes))
	}
	rec := f.changes[0].Changes[0]
	if rec.Action != "UPSERT" {
		t.Errorf("Action = %q, want UPSERT", rec.Action)
	}
	if rec.Name != "_acme-challenge.example.com" || rec.Type != "TXT" {
		t.Errorf("record = %s %s", rec.Name, rec.Type)
	}
	if rec.Value != `"tok-value"` {
		t.Errorf("Value = %q, want quoted token", rec.Value)
	}
	if !strings.Contains(f.auths[0], "AWS4-HMAC-SHA256 Credential=AKID/") {
		t.Errorf("request not signed: %q", f.auths[0])
	}
}

func TestRoute53WaitsForInSync(t *testing.T) {
	route53PollInterval = 10 * time.Millisecond
	defer func() { route53PollInterval = 5 * time.Second }()

	f := &fakeRoute53{statuses: []string{"PENDING", "PENDING", "INSYNC"}}
	r := newTestRoute53(t, f)
	if err := r.SetTXT(t.Context(), "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) != 0 {
		t.Errorf("GetChange stopped early: %v left unconsumed", f.statuses)
	}
}

func TestRoute53CleanupTXT(t *testing.T) {
	f := &fakeRoute53{}
	r := newTestRoute53(t, f)
	if err := r.CleanupTXT(t.Context(), "_acme-challenge.example.com", "tok"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.changes[0].Changes[0].Action; got != "DELETE" {
		t.Errorf("Action = %q, want DELETE", got)
	}
}

func TestRoute53ErrorCarriesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<ErrorResponse>SignatureDoesNotMatch</ErrorResponse>", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	r := &Route53{zoneID: "Z", accessKey: "A", secretKey: "S", endpoint: srv.URL, client: srv.Client()}
	err := r.SetTXT(t.Context(), "x.example.com", "v")
	if err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("err = %v, want the response body in the message", err)
	}
}
