package nitrokit

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Healthz answers a liveness probe with 200 and "ok". Register it as
// mux.HandleFunc("GET /healthz", nitrokit.Healthz). It reports that the
// process is serving requests, nothing more — a handler that checks
// dependencies belongs to the app.
func Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, "ok\n")
}

// HealthProbe dials the server's own /healthz, backing a -healthcheck
// flag for a Docker HEALTHCHECK: main runs the probe instead of the
// server and exits nonzero on error. addr is the server's listen address;
// the probe talks to loopback on its port, because the configured host
// may be a wildcard bind.
func HealthProbe(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: status %d", resp.StatusCode)
	}
	return nil
}
