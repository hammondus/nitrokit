package nitrokit_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hammondus/nitrokit"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	nitrokit.WriteJSON(rec, 201, map[string]int{"n": 7})
	if rec.Code != 201 {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"n":7}` {
		t.Errorf("body = %q", got)
	}
}

func TestJSONError(t *testing.T) {
	rec := httptest.NewRecorder()
	nitrokit.JSONError(rec, 404, "no such thing")
	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"no such thing"}` {
		t.Errorf("body = %q", got)
	}
}

func TestReadJSON(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	tests := []struct {
		name       string
		body       string
		ctype      string
		wantOK     bool
		wantStatus int
	}{
		{"valid", `{"name":"x"}`, "application/json", true, 200},
		{"charset suffix accepted", `{"name":"x"}`, "application/json; charset=utf-8", true, 200},
		{"wrong content type", `{"name":"x"}`, "text/plain", false, 415},
		{"form content type", `name=x`, "application/x-www-form-urlencoded", false, 415},
		{"unknown field", `{"name":"x","extra":1}`, "application/json", false, 400},
		{"malformed", `{`, "application/json", false, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.ctype)
			rec := httptest.NewRecorder()
			var p payload
			ok := nitrokit.ReadJSON(rec, req, &p, nitrokit.MaxJSONBody)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (body %q)", ok, tt.wantOK, rec.Body)
			}
			if !ok && rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if ok && p.Name != "x" {
				t.Errorf("decoded name = %q, want x", p.Name)
			}
		})
	}
}

func TestReadJSONBodyCap(t *testing.T) {
	big := `{"name":"` + strings.Repeat("a", 1<<20) + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	var p struct {
		Name string `json:"name"`
	}
	if nitrokit.ReadJSON(rec, req, &p, nitrokit.MaxJSONBody) {
		t.Fatal("a body over the cap was accepted")
	}
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}

	// The same body passes an endpoint whose own budget is bigger.
	req = httptest.NewRequest("POST", "/", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	if !nitrokit.ReadJSON(rec, req, &p, 8<<20) {
		t.Fatalf("a body inside an 8 MiB budget was rejected: %s", rec.Body)
	}
}

// TestWriteJSONMarshalFailure pins marshal-before-write: an unencodable
// value must become a clean 500, not a committed 200 with no body.
func TestWriteJSONMarshalFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	nitrokit.WriteJSON(rec, 200, map[string]any{"bad": make(chan int)})
	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestWriteJSONKeepsStrongerPolicy(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Cache-Control", "no-store, private")
	nitrokit.WriteJSON(rec, 200, map[string]int{"n": 1})
	if got := rec.Header().Get("Cache-Control"); got != "no-store, private" {
		t.Errorf("Cache-Control = %q, handler's policy was overwritten", got)
	}
}

func TestWriteJSONIndent(t *testing.T) {
	rec := httptest.NewRecorder()
	nitrokit.WriteJSONIndent(rec, 200, map[string]int{"n": 7})
	want := "{\n  \"n\": 7\n}\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
