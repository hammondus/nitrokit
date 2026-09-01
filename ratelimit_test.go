// Internal tests: the limiter's clock and bucket map are unexported.
package nitrokit

import (
	"testing"
	"time"
)

// fakeClock lets tests advance time explicitly.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(rate, burst float64) (*Limiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)}
	l := NewLimiter(rate, burst)
	l.now = clock.now
	return l, clock
}

func TestNewLimiterRejectsUselessConfig(t *testing.T) {
	for _, tt := range []struct{ rate, burst float64 }{
		{0, 3}, {-1, 3}, {1, 0}, {1, 0.5},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewLimiter(%v, %v) did not panic", tt.rate, tt.burst)
				}
			}()
			NewLimiter(tt.rate, tt.burst)
		}()
	}
}

func TestBurstThenDeny(t *testing.T) {
	l, _ := newTestLimiter(1, 3)
	for i := range 3 {
		if ok, _ := l.Allow("ip:1.2.3.4"); !ok {
			t.Fatalf("request %d inside burst denied", i+1)
		}
	}
	ok, retry := l.Allow("ip:1.2.3.4")
	if ok {
		t.Fatal("request beyond burst allowed")
	}
	if retry <= 0 || retry > time.Second {
		t.Fatalf("retry-after %v, want (0, 1s]", retry)
	}
}

func TestRefill(t *testing.T) {
	l, clock := newTestLimiter(1, 3)
	for range 3 {
		l.Allow("k")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("bucket should be empty")
	}
	clock.advance(1500 * time.Millisecond)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("token should have refilled after 1.5s at 1/s")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("only ~0.5 tokens should remain")
	}
	// Refill never exceeds the burst cap.
	clock.advance(time.Hour)
	allowed := 0
	for range 10 {
		if ok, _ := l.Allow("k"); ok {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("after long idle, got %d tokens, want burst cap 3", allowed)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	l.Allow("ip:a")
	if ok, _ := l.Allow("ip:a"); ok {
		t.Fatal("ip:a should be exhausted")
	}
	if ok, _ := l.Allow("ip:b"); !ok {
		t.Fatal("ip:b should be unaffected by ip:a")
	}
}

func TestIdleEviction(t *testing.T) {
	l, clock := newTestLimiter(1, 3)
	l.Allow("stale")
	clock.advance(minIdleEvict + sweepInterval)
	l.Allow("fresh") // triggers a sweep
	l.mu.Lock()
	_, staleExists := l.buckets["stale"]
	n := len(l.buckets)
	l.mu.Unlock()
	if staleExists || n != 1 {
		t.Fatalf("stale bucket not evicted: exists=%v len=%d", staleExists, n)
	}
}

// TestEvictionWaitsForFullRefill pins the reason the threshold is not a
// bare constant: eviction grants a fresh burst, so a slow bucket dropped
// at the constant would refill faster by being forgotten.
func TestEvictionWaitsForFullRefill(t *testing.T) {
	// 1 token per hour, burst 5: a full refill takes 5 hours.
	l, clock := newTestLimiter(1.0/3600, 5)
	for range 5 {
		l.Allow("slow")
	}
	clock.advance(minIdleEvict + sweepInterval)
	l.Allow("other") // triggers a sweep
	l.mu.Lock()
	_, exists := l.buckets["slow"]
	l.mu.Unlock()
	if !exists {
		t.Fatal("bucket evicted before its refill time, which would grant a fresh burst early")
	}
	if ok, _ := l.Allow("slow"); ok {
		t.Fatal("slow bucket should still be empty after 15 minutes at 1 token/hour")
	}
}
