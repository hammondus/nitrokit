# nitrokit

nitrokit is a Go library holding the web-server infrastructure that was
duplicated across a family of hand-rolled stdlib HTTP servers. Its
only dependency is `golang.org/x/crypto`, for automatic TLS certificates. It is a kit of parts, not a framework: your project
keeps its own `main` and imports only the pieces it needs. There is no
`nitrokit.App`, no required initialisation order, and no piece that only
works with another piece.

The name `nitro` is reserved for a future generic web server built on this
module. Server-shaped features — routing conventions, app scaffolding,
config files — belong there, not here.

## What's in the kit

| Concern | File | API |
|---|---|---|
| Server lifecycle | `lifecycle.go` | `NewServer` builds an `http.Server` with the house timeouts; `Run` serves one or more servers with signal handling and a bounded 10 s drain — a server with a `TLSConfig` serves TLS from it, so a plain listener and a file-certificate listener run as one call |
| TLS termination | `tls.go` | `RunTLS` is `Run` plus automatic Let's Encrypt certificates and the port-80 challenge/redirect server, for deployments with no proxy in front |
| Wildcard certificates | `dns.go`, `dnscert.go` | DNS-01 issuance for `*.domain` entries: the `DNSSolver` interface plus a `Route53` solver that signs its own requests (`sigv4.go`), no AWS SDK |
| Asset fingerprinting | `assets.go` | `Assets` hashes an embedded tree at startup, serves it with the immutable/one-hour cache split, and generates `?v=` URLs for templates; `DirAssets` is the same contract for a directory on disk, re-hashing when a file changes so dev modes and copy-deployed sites work without a restart |
| Cache policy | `cache.go` | `NoCache`, `NoCachePrivate`, `NoStore` — one helper per policy tier — and `ETagMatch` |
| Client IP | `clientip.go` | `ParseTrustedProxies` builds a trust list from CIDRs and bare addresses; `TrustPrivateProxies` is the explicit "any local/private peer is my proxy" posture; `ClientIP` walks `X-Forwarded-For` from the right and stops at the first untrusted hop |
| Rate limiting | `ratelimit.go` | `Limiter`: an in-process token bucket keyed by string, with idle-key eviction |
| Auth-failure lockout | `faillimit.go` | `FailLimiter` counts failures per key and blocks a key that fails too often in a window; successes cost nothing and clear the strikes — check `Blocked` before the credential compare |
| Template rendering | `render.go` | `ParseTemplates` clones each page onto a shared base layout (or treats pages as standalone documents when there is no `base.html`); `Render` executes into a buffer with an explicit status — error pages are pages — sets the cache policy, and answers `If-None-Match` on a 200 |
| JSON | `json.go` | `WriteJSON` (marshals before committing the status, so an encode failure is a clean 500), `WriteJSONIndent` for endpoints people read raw, `JSONError`, and `ReadJSON` (per-endpoint body cap — pass `MaxJSONBody` unless the endpoint needs its own budget; unknown fields rejected, Content-Type checked) |
| Form bodies | `form.go` | `ReadForm` parses a capped form body, dispatching on the Content-Type so multipart forms parse instead of silently reading as empty |
| Streaming | `writebudget.go` | `WriteBudget` renews the write deadline as writes make progress — the pair to a zeroed `WriteTimeout` on servers that stream |
| Config | `env.go` | `EnvOr`, plus typed `EnvInt`, `EnvFloat`, `EnvBool`, `EnvDuration` that return an error on a malformed value |
| Middleware | `middleware.go` | `SecureHeaders` (CSP and Permissions-Policy as parameters, empty means the defaults; nosniff, referrer), `AccessLog`, and `HSTS` for servers that terminate their own TLS |
| Health | `health.go` | `Healthz` handler and `HealthProbe`, the loopback self-probe behind a Docker `HEALTHCHECK` |

Each piece carries its full contract in its doc comment; `go doc
github.com/hammondus/nitrokit` lists the surface.

## Example

A minimal server using most of the kit:

```go
package main

import (
	"context"
	"embed"
	"flag"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"net/http"

	"github.com/hammondus/nitrokit"
)

//go:embed static templates
var embedded embed.FS

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the running server and exit")
	flag.Parse()
	addr := nitrokit.EnvOr("APP_ADDR", ":8080")

	// Backs the Docker HEALTHCHECK: the container runs the same binary
	// with -healthcheck and exits by the probe's error.
	if *healthcheck {
		if err := nitrokit.HealthProbe(addr); err != nil {
			log.Fatal(err)
		}
		return
	}

	staticFS, _ := fs.Sub(embedded, "static")
	assets, err := nitrokit.NewAssets(staticFS, "/static/")
	if err != nil {
		log.Fatal(err)
	}

	tmplFS, _ := fs.Sub(embedded, "templates")
	tmpl, err := nitrokit.ParseTemplates(tmplFS, template.FuncMap{"asset": assets.URL})
	if err != nil {
		log.Fatal(err)
	}

	trust, err := nitrokit.ParseTrustedProxies(nitrokit.EnvOr("APP_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"))
	if err != nil {
		log.Fatal(err)
	}
	limiter := nitrokit.NewLimiter(1, 5) // 1 request/s, burst 5

	logger := slog.Default()
	mux := http.NewServeMux()
	mux.Handle("GET /static/", assets)
	mux.HandleFunc("GET /healthz", nitrokit.Healthz)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := limiter.Allow(trust.ClientIP(r).String()); !ok {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		if err := tmpl.Render(w, r, "home.html", nil); err != nil {
			logger.Error("render", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})

	srv := nitrokit.NewServer(addr, nitrokit.AccessLog(logger, nitrokit.SecureHeaders("", "", mux)))
	logger.Info("listening", "addr", addr)
	if err := nitrokit.Run(context.Background(), srv); err != nil {
		log.Fatal(err)
	}
	logger.Info("shutdown complete")
}
```

`Run` installs the SIGINT/SIGTERM handler itself and returns nil after a
clean drain, so this `main` is also the whole shutdown story.

## Two listeners

`Run` is variadic, and a server whose `TLSConfig` is non-nil is served
with `ListenAndServeTLS` from that config. So a plain listener plus a
local-certificate listener (mkcert files for LAN testing, or TLS
terminated by something that hands you files) share one signal handler
and one drain:

```go
cert, err := tls.LoadX509KeyPair("certs/cert.pem", "certs/key.pem")
if err != nil {
	log.Fatal(err)
}
tlsSrv := nitrokit.NewServer(":8443", handler)
tlsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
err = nitrokit.Run(context.Background(), srv, tlsSrv)
```

A server that streams server-sent events must set `WriteTimeout` to 0
(see `NewServer`), and should close its streams from
`srv.RegisterOnShutdown` — an open stream counts as in flight and
otherwise holds every stop for the full 10 s drain.

## Serving TLS without a proxy

Behind nginx proxy manager, use `Run` and let the proxy terminate TLS.
For a host with no proxy in front, replace the `Run` call:

```go
err = nitrokit.RunTLS(context.Background(), srv, nitrokit.ACME{
	Hosts:    []string{"example.com"},
	CacheDir: "/data/certs", // must persist across restarts — a Docker volume
	Email:    "you@example.com",
})
```

with `srv` listening on `":443"` and its handler wrapped in
`nitrokit.HSTS`. `RunTLS` obtains and renews certificates automatically
and runs a second server on port 80 for ACME challenges and the HTTPS
redirect; both drain together on shutdown. The host must be reachable
from the internet on ports 80 and 443, and calling `RunTLS` accepts
Let's Encrypt's terms of service.

`CacheDir` is required. Without persistence every restart requests fresh
certificates, and Let's Encrypt's rate limits turn a few redeploys into
an outage.

### Wildcard certificates

A wildcard needs the DNS-01 challenge, which needs API access to the
zone's DNS. List the wildcard as its own host entry and provide a solver:

```go
solver, err := nitrokit.NewRoute53("Z0123456789ABC") // hosted zone ID
if err != nil {
	log.Fatal(err)
}
err = nitrokit.RunTLS(context.Background(), srv, nitrokit.ACME{
	Hosts:    []string{"example.com", "*.example.com"},
	CacheDir: "/data/certs",
	Email:    "you@example.com",
	DNS:      solver,
})
```

The Route 53 solver reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
and optionally `AWS_SESSION_TOKEN` from the environment. Scope the IAM
policy to `route53:ChangeResourceRecordSets` on that one hosted zone plus
`route53:GetChange`, so a leaked key on the web host can edit TXT records
in one zone and nothing else.

A wildcard does not cover its apex — list `example.com` separately, as
above; it validates over HTTP-01 like any exact host. Wildcard issuance
runs in the background because DNS propagation takes minutes: on the
first-ever start, handshakes for wildcard names fail until the
certificate arrives, and renewal failures appear in the server's
`ErrorLog`. For another DNS provider, implement the two-method
`DNSSolver` interface in your project.

## Adding it to a project

If `github.com/hammondus/nitrokit` resolves, pin a version:

```
go get github.com/hammondus/nitrokit@latest
```

If it does not resolve, put a `go.work` in the consuming project's own
directory listing `.` and the path to nitrokit, git-ignore it, and keep it
out of the Docker build context. Never use a `replace` in `go.mod`: a
`replace` travels into the deploy build, where the relative path is wrong.

## Out of scope

Permanent, unless re-decided in `DESIGN-DECISIONS.md`:

- **Auth, sessions, CSRF.** The existing implementations genuinely differ;
  forcing one shape means designing an auth library.
- **Routing.** Stdlib `ServeMux` with method patterns is the house style
  and needs no wrapper.

## Development

- `make test` — vet plus tests, the default check
- `make race` — race detector, required before tagging a release
- `make lint` — gofmt check plus vet
- `make cover` — coverage summary
- `make release` — lint and race, then tagging instructions

Every extraction records the reasoning behind any deviation in
[DESIGN-DECISIONS.md](DESIGN-DECISIONS.md). Read it before changing an
exported signature: once consumers import a tagged version, the API is a
contract.
