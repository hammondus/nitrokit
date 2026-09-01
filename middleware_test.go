package nitrokit_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hammondus/nitrokit"
)

func TestSecureHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	rec := httptest.NewRecorder()
	nitrokit.SecureHeaders("", "", inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	h := rec.Header()
	if got := h.Get("Content-Security-Policy"); got != nitrokit.DefaultCSP {
		t.Errorf("CSP = %q, want DefaultCSP", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := h.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q", got)
	}
	if got := h.Get("Permissions-Policy"); got != nitrokit.DefaultPermissionsPolicy {
		t.Errorf("Permissions-Policy = %q, want DefaultPermissionsPolicy", got)
	}

	rec = httptest.NewRecorder()
	custom := "camera=(self), geolocation=()"
	nitrokit.SecureHeaders("default-src 'self'", custom, inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("custom CSP = %q", got)
	}
	if got := rec.Header().Get("Permissions-Policy"); got != custom {
		t.Errorf("custom Permissions-Policy = %q, want %q", got, custom)
	}
}

func TestHSTS(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	rec := httptest.NewRecorder()
	nitrokit.HSTS(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("Strict-Transport-Security = %q, want max-age=31536000", got)
	}
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	rec := httptest.NewRecorder()
	nitrokit.AccessLog(log, inner).ServeHTTP(rec, httptest.NewRequest("GET", "/missing", nil))

	line := buf.String()
	for _, want := range []string{"method=GET", "path=/missing", "status=404"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q missing %q", line, want)
		}
	}
}

func TestAccessLogDefaultsTo200(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	// The handler never calls WriteHeader.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	nitrokit.AccessLog(log, inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("log line %q missing status=200", buf.String())
	}
}

// TestAccessLogUnwrap pins the Unwrap method: an SSE handler flushing
// through http.ResponseController must still work under the middleware.
func TestAccessLogUnwrap(t *testing.T) {
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	var flushErr error
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("event: ping\n\n"))
		flushErr = http.NewResponseController(w).Flush()
	})
	nitrokit.AccessLog(log, inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if flushErr != nil {
		t.Fatalf("Flush through the middleware: %v", flushErr)
	}
}
