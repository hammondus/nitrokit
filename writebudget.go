package nitrokit

import (
	"fmt"
	"net/http"
	"time"
)

// WriteBudget wraps next so that every write renews the connection's
// write deadline by budget. It exists for handlers whose responses
// outlive any fixed WriteTimeout — server-sent event streams, large
// downloads, proxied responses. A server-wide WriteTimeout bounds the
// whole response and so must be 0 for those handlers, which silently
// gives up slow-client protection everywhere; WriteBudget restores it
// with nginx's send_timeout semantics: the response may take as long as
// it takes, but any single write that makes no progress for budget kills
// the connection.
//
// Use it as the pair to a zeroed WriteTimeout:
//
//	srv := nitrokit.NewServer(addr, nitrokit.WriteBudget(30*time.Second, mux))
//	srv.WriteTimeout = 0
//
// The deadline is renewed at most once a second, so a handler writing in
// small chunks does not pay a syscall per write. The wrapper keeps
// http.ResponseController working through it (Unwrap), and a
// ResponseWriter that cannot take a deadline — an httptest recorder —
// just runs without one.
func WriteBudget(budget time.Duration, next http.Handler) http.Handler {
	if budget <= 0 {
		panic(fmt.Sprintf("nitrokit.WriteBudget(%v): budget must be positive", budget))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(newBudgetWriter(w, budget, time.Now), r)
	})
}

// budgetWriter renews the connection's write deadline as writes make
// progress, at most once a second.
type budgetWriter struct {
	http.ResponseWriter
	rc     *http.ResponseController
	budget time.Duration
	last   time.Time
	now    func() time.Time // injectable clock for tests
}

func newBudgetWriter(w http.ResponseWriter, budget time.Duration, now func() time.Time) *budgetWriter {
	b := &budgetWriter{ResponseWriter: w, rc: http.NewResponseController(w), budget: budget, now: now}
	b.bump()
	return b
}

func (b *budgetWriter) bump() {
	now := b.now()
	if now.Sub(b.last) >= time.Second {
		// Ignored error: a connection that cannot take a deadline just
		// runs without one.
		_ = b.rc.SetWriteDeadline(now.Add(b.budget))
		b.last = now
	}
}

func (b *budgetWriter) Write(p []byte) (int, error) {
	b.bump()
	return b.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the underlying writer, so
// flushing (server-sent events) keeps working under the middleware.
func (b *budgetWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }
