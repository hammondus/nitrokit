package nitrokit

import (
	"log/slog"
	"net/http"
	"time"
)

// DefaultCSP locks a server-rendered site to same-origin everything: no
// fonts, no analytics, no third-party anything. Sites that load more pass
// their own policy to SecureHeaders — start from this and widen one
// directive at a time.
//
// form-action is 'self' rather than 'none' because house sites post forms
// back to themselves; the explicit allowlist of one means a form that
// ever tried to post elsewhere would be blocked by the browser.
const DefaultCSP = "default-src 'none'; " +
	"style-src 'self'; script-src 'self'; img-src 'self'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// DefaultPermissionsPolicy turns off the powerful browser features no
// house site uses: location, camera, microphone, and Chrome's FLoC
// cohort. An app that uses one of these — in-page QR scanning needs
// camera=(self) — passes its own policy to SecureHeaders; like the CSP,
// start from this and widen one feature at a time.
const DefaultPermissionsPolicy = "geolocation=(), camera=(), microphone=(), interest-cohort=()"

// SecureHeaders sets the house security headers at one chokepoint rather
// than per handler. An empty csp means DefaultCSP; an empty permissions
// means DefaultPermissionsPolicy.
func SecureHeaders(csp, permissions string, next http.Handler) http.Handler {
	if csp == "" {
		csp = DefaultCSP
	}
	if permissions == "" {
		permissions = DefaultPermissionsPolicy
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		// `same-origin`, NOT `no-referrer` — and the difference broke a
		// contact form in production. Per the Fetch spec, a non-CORS POST
		// (an ordinary form submit) serializes its Origin header as
		// "null" when the page's referrer policy is no-referrer, so every
		// browser failed the handler's own origin check while curl,
		// writing the header by hand, passed. Toward other sites the two
		// policies are identical: neither ever sends a referrer
		// cross-origin.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", permissions)
		next.ServeHTTP(w, r)
	})
}

// HSTS sets Strict-Transport-Security for one year, so a browser that has
// seen the site once refuses to talk plain HTTP to it. Wrap the handler
// only when the server terminates TLS itself (RunTLS): behind a proxy the
// terminator owns that policy, and it is deliberately not part of
// SecureHeaders for that reason. No includeSubDomains and no preload —
// both widen the promise to hosts this server may not control, and
// neither is easy to walk back.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the status a handler writes, defaulting to 200
// for handlers that never call WriteHeader.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.NewResponseController reach the underlying writer, so
// per-write deadlines and flushing (server-sent events) keep working
// under the middleware.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// AccessLog logs one line per request at info level: method, path,
// status, duration.
func AccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Info("req",
			"method", r.Method, "path", r.URL.Path,
			"status", rec.status, "dur", time.Since(start).Round(time.Microsecond))
	})
}
