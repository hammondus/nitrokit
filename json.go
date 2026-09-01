package nitrokit

import (
	"encoding/json"
	"net/http"
	"strings"
)

// MaxJSONBody is the default request-body cap to pass to ReadJSON. 1 MiB
// covers every surveyed API's largest legitimate request with two orders
// of magnitude to spare; an endpoint whose requests are bigger — a bulk
// import, a full-vault restore — passes its own budget instead.
const MaxJSONBody = 1 << 20

// WriteJSON writes v as a JSON response with the given status. Responses
// are marked no-store unless the handler already set a Cache-Control —
// API responses describe state at one moment, and a cached one is a
// stale one, but a handler with a stronger opinion (no-store, private on
// a per-user endpoint) keeps it.
//
// v is marshalled before anything is written, so a marshal failure
// becomes a clean 500 instead of a truncated 200 with a committed status
// line.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	writeJSONBytes(w, status, v, json.Marshal)
}

// WriteJSONIndent is WriteJSON with two-space indentation, for endpoints
// people read directly — curl output, a browser tab. Machine clients
// parse either form; the extra bytes are the cost of legibility.
func WriteJSONIndent(w http.ResponseWriter, status int, v any) {
	writeJSONBytes(w, status, v, func(v any) ([]byte, error) {
		return json.MarshalIndent(v, "", "  ")
	})
}

func writeJSONBytes(w http.ResponseWriter, status int, v any, marshal func(any) ([]byte, error)) {
	b, err := marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	// The trailing newline keeps curl output ending cleanly, matching
	// what json.Encoder always emitted.
	b = append(b, '\n')
	// A write error here means the client went away; the response is
	// committed, so there is nothing better to send.
	_, _ = w.Write(b)
}

// JSONError writes {"error": msg} with the given status.
func JSONError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// ReadJSON decodes a JSON request body of at most maxBytes into dst,
// rejecting unknown fields. On failure it writes the error response
// itself and returns false — the caller returns without writing anything.
//
// The cap is per endpoint, because the right budget is a property of the
// request, not the module: pass MaxJSONBody unless the endpoint's largest
// legitimate request is bigger. It is explicit at every call site so a
// reviewer can audit each endpoint's budget without chasing a default.
//
// The required application/json Content-Type doubles as CSRF protection:
// a cross-origin HTML form cannot send that type without a CORS
// preflight, so a state-changing JSON endpoint checked this way cannot be
// driven by a form on someone else's page.
func ReadJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		JSONError(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}
