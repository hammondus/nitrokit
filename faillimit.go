package nitrokit

import (
	"fmt"
	"sync"
	"time"
)

// FailLimiter throttles authentication guessing: it counts *failures* per
// key and blocks a key that fails limit times inside a rolling window,
// until the window rolls over. It is not a rate limiter — successful
// requests cost nothing, so legitimate traffic is never slowed, and a
// success clears the key's strikes entirely (someone who fumbles a token
// a few times while setting up should not carry them).
//
// Key by client IP (ClientIP().String()) for token or login endpoints.
// The handler's order matters: check Blocked *before* running the
// credential compare, so an over-limit request learns nothing about its
// guess; call Fail on a wrong credential and Pass on a right one.
//
// This slows one address, which is the honest bar for an in-process
// limiter: a distributed guesser isn't stopped, and the credential's own
// entropy has to carry that load.
type FailLimiter struct {
	limit  int
	window time.Duration

	mu    sync.Mutex
	fails map[string]*failTrack

	now func() time.Time // injectable clock for tests
}

type failTrack struct {
	count       int
	windowStart time.Time
}

// maxFailKeys bounds the tracked-key map. A flood of distinct keys (a
// botnet) sweeps expired entries first and then evicts arbitrary ones:
// losing a counter weakens limiting far less than unbounded growth
// weakens the server.
const maxFailKeys = 4096

// NewFailLimiter returns a limiter that blocks a key after limit failures
// within window. It panics when limit is below 1 or window is not
// positive, because either configures a limiter that blocks nothing — a
// startup mistake, not a runtime condition.
func NewFailLimiter(limit int, window time.Duration) *FailLimiter {
	if limit < 1 || window <= 0 {
		panic(fmt.Sprintf("nitrokit.NewFailLimiter(%d, %v): limit must be at least 1 and window positive", limit, window))
	}
	return &FailLimiter{
		limit:  limit,
		window: window,
		fails:  map[string]*failTrack{},
		now:    time.Now,
	}
}

// Blocked reports whether key has exhausted its failure budget for the
// current window. Expired windows are reset here, lazily.
func (l *FailLimiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.fails[key]
	if !ok {
		return false
	}
	if l.now().Sub(t.windowStart) >= l.window {
		delete(l.fails, key)
		return false
	}
	return t.count >= l.limit
}

// Fail records one failed attempt for key.
func (l *FailLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	t, ok := l.fails[key]
	if ok && now.Sub(t.windowStart) < l.window {
		t.count++
		return
	}
	if len(l.fails) >= maxFailKeys {
		for k, v := range l.fails {
			if now.Sub(v.windowStart) >= l.window {
				delete(l.fails, k)
			}
		}
		for k := range l.fails {
			if len(l.fails) < maxFailKeys {
				break
			}
			delete(l.fails, k)
		}
	}
	l.fails[key] = &failTrack{count: 1, windowStart: now}
}

// Pass clears key's strikes after a successful attempt.
func (l *FailLimiter) Pass(key string) {
	l.mu.Lock()
	delete(l.fails, key)
	l.mu.Unlock()
}
