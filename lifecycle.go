package nitrokit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// NewServer returns an http.Server for addr and handler with the house
// timeouts set. Timeouts are set because the listener faces a reverse
// proxy, not only trusted callers: without them a stalled connection holds
// a goroutine and a file descriptor indefinitely.
//
// The values suit a page-serving app behind nginx. Adjust fields on the
// returned server where a workload needs different behaviour. In
// particular, a server that streams — server-sent events, websockets,
// large downloads — must set WriteTimeout to 0, because a global write
// timeout cuts the stream; wrap the handler in WriteBudget to get
// per-write slow-client protection back.
func NewServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Longer than a page render needs, so a handler that talks to an
		// upstream service synchronously (SMTP, a payment API) can still
		// return a real success or failure rather than a cut connection.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// shutdownGrace bounds the drain after a stop signal. Deployments that
// need longer must also raise the supervisor's kill timeout (docker stop
// sends SIGKILL after 10 seconds by default), so the two budgets are
// coupled and this one is not worth a parameter.
const shutdownGrace = 10 * time.Second

// Run serves the given servers until ctx is cancelled, the process
// receives SIGINT or SIGTERM, or any listener stops on its own, then
// closes every listener and gives in-flight requests up to 10 seconds to
// finish, draining all servers concurrently within that one budget. Run
// returns nil after a clean drain, the first listener's error if serving
// fails, and a shutdown error if the drain runs out of time — in that
// case in-flight connections were closed mid-request.
//
// A server whose TLSConfig is non-nil is served with ListenAndServeTLS,
// taking its certificates from that config (Certificates, or
// GetCertificate); every other server is served with ListenAndServe. This
// is how one call runs the common listener pair — plain HTTP plus a
// second server carrying file-loaded certificates. For automatic
// certificates, use RunTLS instead.
//
// Run installs the signal handler itself, so a caller with no cancellation
// of its own passes context.Background(). During the drain the default
// signal disposition is restored, so a second signal ends the process
// immediately.
//
// A long-lived response — a server-sent event stream — counts as an
// in-flight request, so an open stream holds the drain for the full 10
// seconds on every stop. A server that streams should close its streams
// when the drain starts: register the closer with srv.RegisterOnShutdown,
// and have each stream handler return when told.
func Run(ctx context.Context, servers ...*http.Server) error {
	if len(servers) == 0 {
		return errors.New("nitrokit: Run called with no servers")
	}
	entries := make([]serverEntry, len(servers))
	for i, srv := range servers {
		serve := srv.ListenAndServe
		if srv.TLSConfig != nil {
			serve = func() error { return srv.ListenAndServeTLS("", "") }
		}
		entries[i] = serverEntry{srv, serve}
	}
	return runAll(ctx, entries...)
}

// serverEntry pairs a server with how to start it, because plain and TLS
// servers start differently but drain identically.
type serverEntry struct {
	srv   *http.Server
	serve func() error
}

// runAll is the one lifecycle implementation behind Run and RunTLS: serve
// every server until ctx is cancelled, a signal arrives, or any listener
// stops on its own, then take them all down together within one shared
// grace budget.
func runAll(ctx context.Context, servers ...serverEntry) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			err := s.serve()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}()
	}

	received := 0
	var serveErr error
	select {
	case serveErr = <-errc:
		received++
	case <-ctx.Done():
	}

	// Restore default signal handling before the drain, so a second
	// signal force-quits instead of being swallowed.
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		shutdownErr error
	)
	for _, s := range servers {
		wg.Go(func() {
			// Concurrent, not sequential: a serial loop would let one slow
			// drain eat the whole budget before the next Shutdown starts.
			if err := s.srv.Shutdown(shutdownCtx); err != nil {
				mu.Lock()
				if shutdownErr == nil {
					shutdownErr = fmt.Errorf("shutdown: %w", err)
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	for ; received < len(servers); received++ {
		if err := <-errc; err != nil && serveErr == nil {
			serveErr = err
		}
	}
	// A listener that failed outright (port in use) matters more than a
	// drain that ran out of time because of it.
	if serveErr != nil {
		return serveErr
	}
	return shutdownErr
}
