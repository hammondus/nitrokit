package nitrokit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
)

// Templates is one parsed template set per page, each page cloned onto a
// shared base layout so pages cannot collide on block names — every page
// may define a block called "content" without the last one parsed
// winning.
type Templates struct {
	pages    map[string]*template.Template
	partials *template.Template
	layout   bool // true when base.html exists and pages render through it
}

// ParseTemplates parses a flat directory of templates. fsys is the
// directory holding the files (use fs.Sub for an embedded tree):
//
//	sub, _ := fs.Sub(embedded, "templates")
//	tmpl, err := nitrokit.ParseTemplates(sub, funcs)
//
// base.html, when present, is the layout every page is cloned onto; with
// no base.html each page is a standalone document rendered by its own
// name — for the site whose pages share nothing. Files starting with "_"
// are partials, parsed into every page and into a standalone set for
// fragment responses (htmx). Every other *.html file is a page, keyed by
// its file name ("home.html").
func ParseTemplates(fsys fs.FS, funcs template.FuncMap) (*Templates, error) {
	var base *template.Template
	if _, err := fs.Stat(fsys, "base.html"); err == nil {
		base, err = template.New("base.html").Funcs(funcs).ParseFS(fsys, "base.html")
		if err != nil {
			return nil, err
		}
	}

	all, err := fs.Glob(fsys, "*.html")
	if err != nil {
		return nil, err
	}
	var pageFiles, partialFiles []string
	for _, name := range all {
		switch {
		case name == "base.html":
		case strings.HasPrefix(name, "_"):
			partialFiles = append(partialFiles, name)
		default:
			pageFiles = append(pageFiles, name)
		}
	}

	partials := template.New("partials").Funcs(funcs)
	if len(partialFiles) > 0 {
		if partials, err = partials.ParseFS(fsys, partialFiles...); err != nil {
			return nil, err
		}
		if base != nil {
			if base, err = base.ParseFS(fsys, partialFiles...); err != nil {
				return nil, err
			}
		}
	}

	t := &Templates{pages: map[string]*template.Template{}, partials: partials, layout: base != nil}
	for _, name := range pageFiles {
		var page *template.Template
		if base != nil {
			clone, err := base.Clone()
			if err != nil {
				return nil, err
			}
			page, err = clone.ParseFS(fsys, name)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", name, err)
			}
		} else {
			files := append(append([]string{}, partialFiles...), name)
			page, err = template.New(name).Funcs(funcs).ParseFS(fsys, files...)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", name, err)
			}
		}
		t.pages[name] = page
	}
	if len(t.pages) == 0 {
		return nil, errors.New("no page templates found")
	}
	return t, nil
}

// Render executes a page into a buffer, then writes it with the given
// status, the house cache policy, and — on a 200 — a strong ETag. A
// non-nil error means nothing has been written: the caller logs it and
// responds with http.Error. Buffering is what makes a mid-render failure
// a clean 500 instead of a 200 followed by half a page.
//
// The status is explicit because error and auth pages are pages too: a
// login form re-rendered after a failure is a 401, a rate-limited one a
// 429, a not-found page a 404. Pass http.StatusOK for the ordinary case.
//
// The cache policy is filled in only when the handler has not already set
// one, so the strict cases — NoCachePrivate before rendering an
// authenticated page, NoStore before showing a secret — are opt-in and
// visible at the call site.
//
// no-cache means "always revalidate", and a browser can only revalidate
// against a validator. The page is already buffered, so a strong ETag
// over the bytes costs one hash; without it every navigation is a full
// re-render and re-transfer. Pages marked no-store skip the ETag (they
// must not be stored at all, so a validator would be pointless), and so
// do non-200 pages — a 304 tells the client its stored copy is still
// good, which only makes sense for a page that was good.
//
// A HEAD request gets the full header set, Content-Length included, and
// no body.
func (t *Templates) Render(w http.ResponseWriter, r *http.Request, page string, status int, data any) error {
	tmpl, ok := t.pages[page]
	if !ok {
		return fmt.Errorf("no template %q", page)
	}
	root := page
	if t.layout {
		root = "base.html"
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, root, data); err != nil {
		return fmt.Errorf("render %s: %w", page, err)
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	if h.Get("Cache-Control") == "" {
		NoCache(w)
	}
	// House pages depend on the session cookie. Without Vary a cache keys
	// only on the URL and may hand a response stored under one session to
	// a request carrying another.
	h.Set("Vary", "Cookie")

	if status == http.StatusOK && !strings.Contains(h.Get("Cache-Control"), "no-store") {
		sum := sha256.Sum256(buf.Bytes())
		etag := `"` + hex.EncodeToString(sum[:16]) + `"`
		h.Set("ETag", etag)
		if match := r.Header.Get("If-None-Match"); match != "" && ETagMatch(match, etag) {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}

	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return nil
	}
	// A write error here means the client went away; the response is
	// committed, so there is nothing better to send.
	_, _ = w.Write(buf.Bytes())
	return nil
}

// RenderPartial writes a named partial as a fragment response, buffered
// for the same clean-error reason as Render. Fragments are addressed to
// one page state, so the default policy is no-cache, private.
func (t *Templates) RenderPartial(w http.ResponseWriter, name string, data any) error {
	var buf bytes.Buffer
	if err := t.partials.ExecuteTemplate(&buf, name, data); err != nil {
		return fmt.Errorf("render partial %s: %w", name, err)
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	if h.Get("Cache-Control") == "" {
		NoCachePrivate(w)
	}
	_, _ = w.Write(buf.Bytes())
	return nil
}
