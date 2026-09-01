// Package nitrokit provides the web-server infrastructure shared by the
// stdlib HTTP servers under hammondus projects: lifecycle (with or without
// TLS termination), asset fingerprinting and cache policy, trusted-proxy
// client IP, buffered template rendering, env/JSON helpers, access
// logging, security headers, health checks, rate limiting, and
// auth-failure lockout.
//
// It is a set of composable functions, not a framework: each consumer keeps
// its own main and imports only the pieces it needs. Auth, sessions, CSRF,
// and routing are out of scope; see DESIGN-DECISIONS.md.
package nitrokit
