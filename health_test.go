package nitrokit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hammondus/nitrokit"
)

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	nitrokit.Healthz(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Errorf("body = %q, want ok", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestHealthProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", nitrokit.Healthz)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	if err := nitrokit.HealthProbe(addr); err != nil {
		t.Errorf("probe against a healthy server: %v", err)
	}

	// A server without the route reports unhealthy.
	bare := httptest.NewServer(http.NewServeMux())
	defer bare.Close()
	if err := nitrokit.HealthProbe(strings.TrimPrefix(bare.URL, "http://")); err == nil {
		t.Error("probe against a server with no /healthz reported healthy")
	}

	if err := nitrokit.HealthProbe("no-port-here"); err == nil {
		t.Error("probe accepted an address without a port")
	}
}
