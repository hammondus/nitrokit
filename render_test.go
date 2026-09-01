package nitrokit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/hammondus/nitrokit"
)

var tmplFS = fstest.MapFS{
	"base.html": {Data: []byte(`<main>{{block "content" .}}{{end}}</main>`)},
	// Both pages define "content"; per-page cloning is what keeps the
	// second parse from overwriting the first.
	"home.html":  {Data: []byte(`{{define "content"}}home: {{.Name}} {{template "row" .Name}}{{end}}`)},
	"about.html": {Data: []byte(`{{define "content"}}about{{end}}`)},
	"_row.html":  {Data: []byte(`{{define "row"}}[row {{.}}]{{end}}`)},
}

func newTestTemplates(t *testing.T) *nitrokit.Templates {
	t.Helper()
	tmpl, err := nitrokit.ParseTemplates(tmplFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func TestParseTemplatesErrors(t *testing.T) {
	if _, err := nitrokit.ParseTemplates(fstest.MapFS{}, nil); err == nil {
		t.Error("an empty directory accepted")
	}
	noPages := fstest.MapFS{"base.html": {Data: []byte(`x`)}}
	if _, err := nitrokit.ParseTemplates(noPages, nil); err == nil {
		t.Error("a directory with no pages accepted")
	}
	badBase := fstest.MapFS{
		"base.html": {Data: []byte(`{{end}}`)},
		"home.html": {Data: []byte(`x`)},
	}
	if _, err := nitrokit.ParseTemplates(badBase, nil); err == nil {
		t.Error("a broken base.html accepted")
	}
}

// TestParseTemplatesStandalone pins the no-layout mode: with no
// base.html each page is its own document, rendered by its own name,
// with partials still available.
func TestParseTemplatesStandalone(t *testing.T) {
	fsys := fstest.MapFS{
		"one.html":  {Data: []byte(`<p>one {{template "row" .}}</p>`)},
		"two.html":  {Data: []byte(`<p>two</p>`)},
		"_row.html": {Data: []byte(`{{define "row"}}[row {{.}}]{{end}}`)},
	}
	tmpl, err := nitrokit.ParseTemplates(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "one.html", http.StatusOK, "x"); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Body.String(), "<p>one [row x]</p>"; got != want {
		t.Errorf("standalone page = %q, want %q", got, want)
	}
}

func TestRenderPagesDoNotCollide(t *testing.T) {
	tmpl := newTestTemplates(t)

	rec := httptest.NewRecorder()
	err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "home.html", http.StatusOK, struct{ Name string }{"n1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Body.String(), "<main>home: n1 [row n1]</main>"; got != want {
		t.Errorf("home = %q, want %q", got, want)
	}

	rec = httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "about.html", http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Body.String(), "<main>about</main>"; got != want {
		t.Errorf("about = %q, want %q", got, want)
	}
}

func TestRenderHeaders(t *testing.T) {
	tmpl := newTestTemplates(t)
	rec := httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "about.html", http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}
	h := rec.Header()
	if got := h.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if got := h.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Get("Vary"); got != "Cookie" {
		t.Errorf("Vary = %q, want Cookie", got)
	}
	if h.Get("ETag") == "" {
		t.Error("no ETag")
	}
}

func TestRenderKeepsStrongerPolicy(t *testing.T) {
	tmpl := newTestTemplates(t)
	rec := httptest.NewRecorder()
	nitrokit.NoStore(rec)
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "about.html", http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store, private" {
		t.Errorf("Cache-Control = %q, handler's no-store was overwritten", got)
	}
	// no-store pages must not carry a validator: they are never stored,
	// so there is nothing to revalidate.
	if got := rec.Header().Get("ETag"); got != "" {
		t.Errorf("ETag = %q on a no-store page, want none", got)
	}
}

func TestRenderRevalidation(t *testing.T) {
	tmpl := newTestTemplates(t)
	rec := httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "about.html", http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}
	etag := rec.Header().Get("ETag")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	if err := tmpl.Render(rec, req, "about.html", http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 304 {
		t.Errorf("status = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 carried a body: %q", rec.Body)
	}
}

// TestRenderStatus pins the reason status is a parameter: error and auth
// pages are pages, and they must not go out as 200 — or gain a validator
// that could later 304 a page that was never good.
func TestRenderStatus(t *testing.T) {
	tmpl := newTestTemplates(t)
	rec := httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "about.html", http.StatusUnauthorized, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Errorf("ETag = %q on a 401 page, want none", got)
	}
	if got, want := rec.Body.String(), "<main>about</main>"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	// If-None-Match must not turn an error page into a 304.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("If-None-Match", "*")
	rec = httptest.NewRecorder()
	if err := tmpl.Render(rec, req, "about.html", http.StatusNotFound, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("conditional error page: status = %d, want 404", rec.Code)
	}
}

func TestRenderHead(t *testing.T) {
	tmpl := newTestTemplates(t)
	rec := httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("HEAD", "/", nil), "about.html", http.StatusOK, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD carried a body: %q", rec.Body)
	}
	if got, want := rec.Header().Get("Content-Length"), "18"; got != want {
		t.Errorf("Content-Length = %q, want %q (len of the rendered page)", got, want)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("HEAD response has no ETag")
	}
}

func TestRenderErrorWritesNothing(t *testing.T) {
	tmpl := newTestTemplates(t)

	rec := httptest.NewRecorder()
	if err := tmpl.Render(rec, httptest.NewRequest("GET", "/", nil), "missing.html", http.StatusOK, nil); err == nil {
		t.Fatal("unknown page did not error")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("unknown page wrote %q", rec.Body)
	}

	// A template that fails mid-execution must leave the response
	// untouched, so the caller can still send a clean 500.
	failing := fstest.MapFS{
		"base.html": {Data: []byte(`<main>{{block "content" .}}{{end}}</main>`)},
		"bad.html":  {Data: []byte(`{{define "content"}}{{.Missing.Deeper}}{{end}}`)},
	}
	ft, err := nitrokit.ParseTemplates(failing, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	if err := ft.Render(rec, httptest.NewRequest("GET", "/", nil), "bad.html", http.StatusOK, struct{}{}); err == nil {
		t.Fatal("failing template did not error")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("failing template wrote %q", rec.Body)
	}
}

func TestRenderPartial(t *testing.T) {
	tmpl := newTestTemplates(t)
	rec := httptest.NewRecorder()
	if err := tmpl.RenderPartial(rec, "row", "r1"); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Body.String(), "[row r1]"; got != want {
		t.Errorf("partial = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache, private" {
		t.Errorf("Cache-Control = %q, want no-cache, private", got)
	}

	if err := tmpl.RenderPartial(httptest.NewRecorder(), "nope", nil); err == nil {
		t.Error("unknown partial did not error")
	}
	if !strings.Contains(tmpl.RenderPartial(httptest.NewRecorder(), "nope", nil).Error(), "nope") {
		t.Error("partial error does not name the template")
	}
}
