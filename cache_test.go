package nitrokit_test

import (
	"net/http/httptest"
	"testing"

	"github.com/hammondus/nitrokit"
)

func TestCacheHelpers(t *testing.T) {
	tests := []struct {
		name string
		set  func(*httptest.ResponseRecorder)
		want string
	}{
		{"NoCache", func(w *httptest.ResponseRecorder) { nitrokit.NoCache(w) }, "no-cache"},
		{"NoCachePrivate", func(w *httptest.ResponseRecorder) { nitrokit.NoCachePrivate(w) }, "no-cache, private"},
		{"NoStore", func(w *httptest.ResponseRecorder) { nitrokit.NoStore(w) }, "no-store, private"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.set(rec)
			if got := rec.Header().Get("Cache-Control"); got != tt.want {
				t.Errorf("Cache-Control = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestETagMatch(t *testing.T) {
	tests := []struct {
		header string
		etag   string
		want   bool
	}{
		{`"abc"`, `"abc"`, true},
		{`"abc"`, `"def"`, false},
		{`"abc", "def"`, `"def"`, true},
		{`W/"abc"`, `"abc"`, true},
		{`*`, `"anything"`, true},
		{``, `"abc"`, false},
		{`"abcd"`, `"abc"`, false},
	}
	for _, tt := range tests {
		if got := nitrokit.ETagMatch(tt.header, tt.etag); got != tt.want {
			t.Errorf("ETagMatch(%q, %q) = %v, want %v", tt.header, tt.etag, got, tt.want)
		}
	}
}
