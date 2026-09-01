// Internal tests: the budget writer's clock is unexported. fakeClock
// comes from ratelimit_test.go.
package nitrokit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// deadlineRecorder records the write deadlines set on it.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func TestWriteBudgetRejectsUselessConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("WriteBudget(0) did not panic")
		}
	}()
	WriteBudget(0, http.NotFoundHandler())
}

func TestWriteBudgetRenewsDeadline(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := newBudgetWriter(rec, 30*time.Second, clock.now)

	if len(rec.deadlines) != 1 {
		t.Fatalf("deadlines after construction = %d, want 1", len(rec.deadlines))
	}
	if want := clock.t.Add(30 * time.Second); !rec.deadlines[0].Equal(want) {
		t.Errorf("deadline = %v, want %v (now + budget)", rec.deadlines[0], want)
	}

	// Rapid writes renew at most once a second, so a chunked writer does
	// not pay a syscall per chunk.
	w.Write([]byte("a"))
	w.Write([]byte("b"))
	if len(rec.deadlines) != 1 {
		t.Fatalf("deadlines after rapid writes = %d, want still 1", len(rec.deadlines))
	}

	clock.advance(1500 * time.Millisecond)
	w.Write([]byte("c"))
	if len(rec.deadlines) != 2 {
		t.Fatalf("deadlines after 1.5s = %d, want 2", len(rec.deadlines))
	}
	if want := clock.t.Add(30 * time.Second); !rec.deadlines[1].Equal(want) {
		t.Errorf("renewed deadline = %v, want %v", rec.deadlines[1], want)
	}
	if got := rec.Body.String(); got != "abc" {
		t.Errorf("body = %q, want abc", got)
	}
}

// TestWriteBudgetWithoutDeadlineSupport pins the fallback: a writer that
// cannot take a deadline (httptest's plain recorder) runs without one
// instead of failing.
func TestWriteBudgetWithoutDeadlineSupport(t *testing.T) {
	h := WriteBudget(30*time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through WriteBudget: %v", err)
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Body.String(); got != "ok" {
		t.Errorf("body = %q, want ok", got)
	}
}
