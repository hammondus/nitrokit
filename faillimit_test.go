// Internal tests: the limiter's clock and map are unexported. fakeClock
// comes from ratelimit_test.go.
package nitrokit

import (
	"fmt"
	"testing"
	"time"
)

func newTestFailLimiter(limit int, window time.Duration) (*FailLimiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	l := NewFailLimiter(limit, window)
	l.now = clock.now
	return l, clock
}

func TestNewFailLimiterRejectsUselessConfig(t *testing.T) {
	for _, tt := range []struct {
		limit  int
		window time.Duration
	}{
		{0, time.Minute}, {-1, time.Minute}, {3, 0}, {3, -time.Second},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewFailLimiter(%d, %v) did not panic", tt.limit, tt.window)
				}
			}()
			NewFailLimiter(tt.limit, tt.window)
		}()
	}
}

func TestFailLimiterBlocksAtLimit(t *testing.T) {
	l, _ := newTestFailLimiter(3, 15*time.Minute)
	for i := range 3 {
		if l.Blocked("ip") {
			t.Fatalf("blocked after %d failures, limit is 3", i)
		}
		l.Fail("ip")
	}
	if !l.Blocked("ip") {
		t.Fatal("not blocked after 3 failures")
	}
	if l.Blocked("other") {
		t.Fatal("an unrelated key is blocked")
	}
}

func TestFailLimiterWindowExpires(t *testing.T) {
	l, clock := newTestFailLimiter(3, 15*time.Minute)
	for range 3 {
		l.Fail("ip")
	}
	clock.advance(15 * time.Minute)
	if l.Blocked("ip") {
		t.Fatal("still blocked after the window rolled over")
	}
	// The expired entry is gone, so the next failure starts a fresh window.
	l.Fail("ip")
	if l.Blocked("ip") {
		t.Fatal("blocked after 1 failure in a fresh window")
	}
}

func TestFailLimiterPassClearsStrikes(t *testing.T) {
	l, _ := newTestFailLimiter(3, 15*time.Minute)
	l.Fail("ip")
	l.Fail("ip")
	l.Pass("ip")
	for i := range 3 {
		if l.Blocked("ip") {
			t.Fatalf("blocked after %d post-Pass failures, limit is 3", i)
		}
		l.Fail("ip")
	}
	if !l.Blocked("ip") {
		t.Fatal("not blocked after 3 failures following a Pass")
	}
}

// TestFailLimiterFailAfterExpiryResets pins the lazy reset in Fail: a
// failure arriving after the window must start a new window at count 1,
// not extend the old one.
func TestFailLimiterFailAfterExpiryResets(t *testing.T) {
	l, clock := newTestFailLimiter(3, 15*time.Minute)
	for range 3 {
		l.Fail("ip")
	}
	clock.advance(15 * time.Minute)
	l.Fail("ip")
	if l.Blocked("ip") {
		t.Fatal("old window's strikes carried into the new one")
	}
}

func TestFailLimiterEvictsAtCap(t *testing.T) {
	l, clock := newTestFailLimiter(1, 15*time.Minute)
	for i := range maxFailKeys {
		l.Fail(fmt.Sprintf("key%d", i))
	}
	// All expired: the next Fail sweeps them instead of evicting live ones.
	clock.advance(15 * time.Minute)
	l.Fail("fresh")
	l.mu.Lock()
	n := len(l.fails)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("map holds %d entries after sweep, want 1", n)
	}

	// A flood of live keys: the map never exceeds the cap.
	for i := range maxFailKeys + 100 {
		l.Fail(fmt.Sprintf("flood%d", i))
	}
	l.mu.Lock()
	n = len(l.fails)
	l.mu.Unlock()
	if n > maxFailKeys {
		t.Fatalf("map holds %d entries, cap is %d", n, maxFailKeys)
	}
}
