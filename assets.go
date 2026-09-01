package nitrokit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Go's built-in extension table has no entry for the web font types, and
// a container image has no /etc/mime.types to fall back on, so without
// these a font is served as application/octet-stream and some browsers
// refuse it.
func init() {
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".woff", "font/woff")
}

// Assets serves a static file tree with content-hashed cache-busting URLs.
// Templates reference files through URL, which appends the hash as a ?v=
// query: a deploy that changes a file changes its URL, so browsers fetch
// it instead of serving the copy they cached an hour ago.
//
// This only works when every page that names the URLs is revalidated on
// load — set NoCache on HTML responses.
type Assets struct {
	prefix string
	files  map[string]*assetFile
}

type assetFile struct {
	body  []byte
	hash  string
	ctype string
}

// NewAssets reads and hashes every file in fsys. prefix is the URL path
// the tree is mounted under and must start with "/":
//
//	static, _ := fs.Sub(embedded, "static")
//	assets, err := nitrokit.NewAssets(static, "/static/")
//	mux.Handle("GET /static/", assets)
//
// Hashing once at startup is correct only because fsys is embedded and
// cannot change without a rebuild. To serve files read from disk at
// runtime, hash per request instead — a startup hash is wrong the moment
// the file is edited under a running server.
//
// Hashing the content, rather than stamping a build version, keeps URLs
// stable across deploys that did not touch the file, and works for a
// plain go build with no version ldflag.
func NewAssets(fsys fs.FS, prefix string) (*Assets, error) {
	if !strings.HasPrefix(prefix, "/") {
		return nil, fmt.Errorf("assets: prefix %q must start with /", prefix)
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	a := &Assets{prefix: prefix, files: map[string]*assetFile{}}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		ctype := mime.TypeByExtension(path.Ext(name))
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		sum := sha256.Sum256(b)
		// 12 hex chars (48 bits): far more than enough to distinguish
		// every deploy of a handful of files, short enough to keep URLs
		// readable.
		a.files[name] = &assetFile{
			body:  b,
			hash:  hex.EncodeToString(sum[:])[:12],
			ctype: ctype,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// URL returns the cache-busting URL for a file, named relative to the tree
// root: URL("app.css") returns "/static/app.css?v=1a2b3c4d5e6f". For a
// name that is not in the tree it returns the plain unversioned path, so a
// typo renders as a visible 404 instead of a versioned URL that never
// existed.
//
// Install it as a template func:
//
//	template.FuncMap{"asset": assets.URL}
func (a *Assets) URL(name string) string {
	f, ok := a.files[name]
	if !ok {
		return a.prefix + name
	}
	return a.prefix + name + "?v=" + f.hash
}

// ServeHTTP serves the tree. A request whose ?v= matches the file's
// current hash names those exact bytes and can never go stale, so it is
// cached for a year and marked immutable. Anything else — a bookmark,
// /favicon.ico, an old page still open in a tab — gets an hour, because
// that URL's content can change under the client.
func (a *Assets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, a.prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, ok := a.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("ETag", `"`+f.hash+`"`)
	h.Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") == f.hash {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "public, max-age=3600")
	}
	// The zero mod time keeps Last-Modified out: the ETag drives
	// revalidation, and embedded files have no meaningful timestamp.
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(f.body))
}

// DirAssets is Assets for a directory on disk — files that can change
// under the running server: a -dev mode serving the working tree, or a
// small site that deploys by copying files. Where Assets hashes once at
// startup (correct only for embedded bytes), DirAssets checks the file on
// every URL call and every request — a stat when the file is unchanged, a
// re-hash when it is — so an edited file gets a new ?v= URL on the next
// page render with no restart.
type DirAssets struct {
	root   *os.Root
	prefix string

	mu    sync.Mutex
	cache map[string]dirHash
}

// dirHash is a file's content hash, valid while size and mtime match.
type dirHash struct {
	size  int64
	mtime time.Time
	hash  string
}

// NewDirAssets serves the tree rooted at dir under the URL prefix, which
// must start with "/". The directory is opened as an os.Root, so a
// request path can never escape it.
func NewDirAssets(dir, prefix string) (*DirAssets, error) {
	if !strings.HasPrefix(prefix, "/") {
		return nil, fmt.Errorf("assets: prefix %q must start with /", prefix)
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &DirAssets{root: root, prefix: prefix, cache: map[string]dirHash{}}, nil
}

// hash returns the current content hash for name, re-reading the file
// only when its size or mtime changed since the last look.
func (a *DirAssets) hash(name string) (string, error) {
	info, err := a.root.Stat(name)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	c, ok := a.cache[name]
	a.mu.Unlock()
	if ok && c.size == info.Size() && c.mtime.Equal(info.ModTime()) {
		return c.hash, nil
	}
	f, err := a.root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	h := hex.EncodeToString(sum.Sum(nil))[:12]
	a.mu.Lock()
	a.cache[name] = dirHash{size: info.Size(), mtime: info.ModTime(), hash: h}
	a.mu.Unlock()
	return h, nil
}

// URL returns the cache-busting URL for a file, hashed from its current
// on-disk content. A missing file returns the plain unversioned path,
// like Assets.URL, so the typo renders as a visible 404.
func (a *DirAssets) URL(name string) string {
	h, err := a.hash(name)
	if err != nil {
		return a.prefix + name
	}
	return a.prefix + name + "?v=" + h
}

// ServeHTTP serves the tree with the same policy split as Assets: a ?v=
// matching the file's current hash names exactly the bytes being served
// (both are checked in this request), so it is immutable; anything else
// gets an hour. The real mod time goes to ServeContent, so Last-Modified
// and range requests work.
func (a *DirAssets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, a.prefix)
	if !ok || name == "" {
		http.NotFound(w, r)
		return
	}
	f, err := a.root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	hash, err := a.hash(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	h := w.Header()
	if ctype := mime.TypeByExtension(path.Ext(name)); ctype != "" {
		h.Set("Content-Type", ctype)
	}
	h.Set("ETag", `"`+hash+`"`)
	h.Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") == hash {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "public, max-age=3600")
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}
