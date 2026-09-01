package nitrokit

import (
	"net/http"
	"strings"
)

// NoCache marks a response as never reusable without revalidation:
// the browser stores it but asks again before showing it. This is the
// house policy for every HTML response, because a server-rendered page
// carries the URLs of every fingerprinted asset it references — serve the
// page stale and the client that most needs the new CSS is the one that
// never asks for it.
//
// Revalidation only works against a validator. Send an ETag or
// Last-Modified with the response, or the round trip is a full
// re-transfer every time.
func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache")
}

// NoCachePrivate is NoCache for authenticated pages: private keeps a
// shared cache or proxy from storing one user's page and handing it to
// another.
func NoCachePrivate(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, private")
}

// NoStore marks a response as never stored at all. Use it only for pages
// that show a secret once — a freshly minted API key, a password-reset
// form — to keep the secret off disk. It also disables the browser's
// back/forward cache, which is why it is not the default for
// authenticated pages.
func NoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
}

// ETagMatch reports whether an If-None-Match header lists etag, which must
// include its surrounding quotes. The header is a comma-separated list and
// may be "*", which matches any existing representation. A weak validator
// ("W/" prefix) compares equal to a strong one here: If-None-Match uses
// the weak comparison by definition.
func ETagMatch(header, etag string) bool {
	for candidate := range strings.SplitSeq(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}
