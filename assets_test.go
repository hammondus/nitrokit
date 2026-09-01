package nitrokit_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hammondus/nitrokit"
)

var testFS = fstest.MapFS{
	"app.css":      {Data: []byte("body { color: red }")},
	"img/logo.png": {Data: []byte("not really a png")},
}

func newTestAssets(t *testing.T) *nitrokit.Assets {
	t.Helper()
	a, err := nitrokit.NewAssets(testFS, "/static/")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// hashFromURL extracts the ?v= value that URL generated, so tests do not
// hard-code the hash.
func hashFromURL(t *testing.T, u string) string {
	t.Helper()
	_, v, ok := strings.Cut(u, "?v=")
	if !ok {
		t.Fatalf("no ?v= in %q", u)
	}
	return v
}

func TestNewAssetsRejectsRelativePrefix(t *testing.T) {
	if _, err := nitrokit.NewAssets(testFS, "static/"); err == nil {
		t.Fatal("NewAssets accepted a prefix without a leading /")
	}
}

func TestAssetsURL(t *testing.T) {
	a := newTestAssets(t)

	u := a.URL("app.css")
	if !strings.HasPrefix(u, "/static/app.css?v=") {
		t.Errorf("URL(app.css) = %q, want /static/app.css?v=<hash>", u)
	}
	if h := hashFromURL(t, u); len(h) != 12 {
		t.Errorf("hash %q has length %d, want 12", h, len(h))
	}
	if u := a.URL("img/logo.png"); !strings.HasPrefix(u, "/static/img/logo.png?v=") {
		t.Errorf("URL(img/logo.png) = %q, want versioned nested path", u)
	}

	// A typo returns the plain path, so the 404 is visible in the page.
	if got, want := a.URL("missing.css"), "/static/missing.css"; got != want {
		t.Errorf("URL(missing.css) = %q, want %q", got, want)
	}
}

func TestAssetsServeHTTP(t *testing.T) {
	a := newTestAssets(t)
	v := hashFromURL(t, a.URL("app.css"))

	tests := []struct {
		name         string
		path         string
		status       int
		cacheControl string
	}{
		{"current version", "/static/app.css?v=" + v, 200, "public, max-age=31536000, immutable"},
		{"no version", "/static/app.css", 200, "public, max-age=3600"},
		{"stale version", "/static/app.css?v=000000000000", 200, "public, max-age=3600"},
		{"nested file", "/static/img/logo.png", 200, "public, max-age=3600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.ServeHTTP(rec, httptest.NewRequest("GET", tt.path, nil))
			resp := rec.Result()
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
			if got := resp.Header.Get("Cache-Control"); got != tt.cacheControl {
				t.Errorf("Cache-Control = %q, want %q", got, tt.cacheControl)
			}
			if resp.Header.Get("ETag") == "" {
				t.Error("no ETag header")
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

func TestAssetsServeHTTPBody(t *testing.T) {
	a := newTestAssets(t)

	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/static/app.css", nil))
	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "body { color: red }"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/css") {
		t.Errorf("Content-Type = %q, want text/css", got)
	}
}

func TestAssetsServeHTTPNotFound(t *testing.T) {
	a := newTestAssets(t)
	for _, path := range []string{"/static/missing.css", "/elsewhere/app.css"} {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestAssetsRevalidation(t *testing.T) {
	a := newTestAssets(t)

	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/static/app.css", nil))
	etag := rec.Result().Header.Get("ETag")

	req := httptest.NewRequest("GET", "/static/app.css", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("revalidation = %d, want 304", rec.Code)
	}
}

func newTestDirAssets(t *testing.T) (*nitrokit.DirAssets, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.css"), []byte("body { color: red }"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := nitrokit.NewDirAssets(dir, "/static/")
	if err != nil {
		t.Fatal(err)
	}
	return a, dir
}

// TestDirAssetsURLTracksEdits pins the reason DirAssets exists: an edit
// under the running server must produce a new ?v= URL with no restart.
func TestDirAssetsURLTracksEdits(t *testing.T) {
	a, dir := newTestDirAssets(t)
	u1 := a.URL("app.css")
	if !strings.Contains(u1, "/static/app.css?v=") {
		t.Fatalf("URL = %q, want /static/app.css?v=<hash>", u1)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.css"), []byte("body { color: blue }"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force a distinct mtime in case the writes landed in one FS tick.
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "app.css"), later, later); err != nil {
		t.Fatal(err)
	}
	if u2 := a.URL("app.css"); u2 == u1 {
		t.Errorf("URL unchanged after edit: %q", u2)
	}
	if got := a.URL("missing.css"); got != "/static/missing.css" {
		t.Errorf("missing file URL = %q, want plain path", got)
	}
}

func TestDirAssetsServe(t *testing.T) {
	a, _ := newTestDirAssets(t)
	hash := strings.TrimPrefix(a.URL("app.css"), "/static/app.css?v=")

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	rec := get("/static/app.css?v=" + hash)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("matching ?v= Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/css") {
		t.Errorf("Content-Type = %q", got)
	}
	if rec.Header().Get("Last-Modified") == "" {
		t.Error("no Last-Modified from a real file")
	}
	if body, _ := io.ReadAll(rec.Body); string(body) != "body { color: red }" {
		t.Errorf("body = %q", body)
	}

	if got := get("/static/app.css").Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("unversioned Cache-Control = %q", got)
	}
	if got := get("/static/app.css?v=stale").Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("stale ?v= Cache-Control = %q, must not be immutable", got)
	}
	if rec := get("/static/nope.css"); rec.Code != 404 {
		t.Errorf("missing file status = %d, want 404", rec.Code)
	}
	// os.Root refuses the escape; it must surface as a 404, not the file.
	if rec := get("/static/../assets_test.go"); rec.Code != 404 {
		t.Errorf("path escape status = %d, want 404", rec.Code)
	}
}
