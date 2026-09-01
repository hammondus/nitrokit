package nitrokit

import (
	"fmt"
	"sync"
	"time"
)

// Limiter is an in-process token-bucket rate limiter keyed by string. It
// hands out tokens at a fixed rate per key, with a burst allowance, and
// periodically evicts idle keys to bound memory.
//
// Key by client IP for per-address limits (ClientIP().String()); a
// per-API-key limit is the same limiter with a different key. In-process
// is the right scope for a single-container deployment: a limiter that
// forgets everything on restart is a fair trade for having no store to
// run.
type Limiter struct {
	rate  float64 // tokens added per second
	burst float64 // bucket capacity

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time

	now func() time.Time // injectable clock for tests
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	sweepInterval = 5 * time.Minute
	minIdleEvict  = 10 * time.Minute
)

// NewLimiter returns a limiter allowing rate tokens per second with the
// given burst. It panics when rate is not positive or burst is below 1,
// because either configures a limiter that can never issue a token — a
// startup mistake, not a runtime condition.
func NewLimiter(rate, burst float64) *Limiter {
	if rate <= 0 || burst < 1 {
		panic(fmt.Sprintf("nitrokit.NewLimiter(%v, %v): rate must be positive and burst at least 1", rate, burst))
	}
	return &Limiter{
		rate:    rate,
		burst:   burst,
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Allow consumes one token for key if available. When denied it returns
// how long the caller should wait before retrying — round it up when
// setting a Retry-After header.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b, exists := l.buckets[key]
	if !exists {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// sweep drops buckets idle long enough to have refilled completely, so a
// flood of distinct keys cannot grow the map without bound. The threshold
// is never shorter than the full refill time: eviction grants a fresh
// burst on the key's next request, so dropping a bucket early would hand
// out tokens sooner than keeping it. Caller holds the mutex.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now
	idle := max(minIdleEvict, time.Duration(l.burst/l.rate*float64(time.Second)))
	for key, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, key)
		}
	}
}
