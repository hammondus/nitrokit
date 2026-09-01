# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

nitrokit is a zero-dependency Go library that extracts the web-server
infrastructure duplicated across ~17 hand-rolled stdlib HTTP servers in the
private workspace. It is a set of composable functions, not a
framework: each consumer keeps its own `main` and imports only the pieces it
needs. The name `nitro` is reserved for a future generic web server that will
be built on this module — server-shaped features (routing conventions, app
scaffolding, config files) belong there, not here.

Before adding or changing any exported API, read `DESIGN-DECISIONS.md` (the
binding scope and API rules) and `private/PROPOSAL.md` (the survey data
behind them).

## This repo is public; `private/` is not

Anything describing the private development environment stays out of
tracked files: names of non-public projects, local paths (`~/dev/...`),
per-project defect attributions, and deployment specifics. The public
modules — ownvault, nitro, mailer, mfa — may be named openly. Everything
else lives in the git-ignored `private/` directory: `PROPOSAL.md` (the
survey), `ADOPTION.md` (per-project conversion notes — update it as
projects convert), `PROVENANCE.md` (the key mapping DESIGN-DECISIONS.md's
anonymised "a surveyed copy" references back to real projects), and
`history.bundle` (the pre-publication git history). When writing a new
DESIGN-DECISIONS.md entry, put the reasoning there in anonymised form and
the attribution in `private/PROVENANCE.md`.

## Commands

- `make test` — `go vet` plus `go test ./...`. The default check.
- `go test -run 'TestName' ./...` — run a single test.
- `make race` — race detector; required before tagging a release.
- `make lint` — gofmt check (fails on unformatted files) plus vet.
- `make cover` — coverage summary; `go tool cover -html=coverage.out` for detail.
- `make build` — compile check only; there is no binary.
- `make release` — runs lint and race, then prints tagging instructions.
  `run`, `docker-build`, `deploy`, and `logs` exist for cross-repo consistency
  but only explain that a library has nothing to run or deploy.

## Rules

- **Stdlib plus `golang.org/x/crypto`, nothing else.** x/crypto exists for
  `acme/autocert` behind `RunTLS` (decided 2026-08-31); it is the one
  dependency exception. Adding any other require to `go.mod` is a design
  change, not a routine edit, and needs a `DESIGN-DECISIONS.md` entry.
- **Out of scope, permanently unless re-decided:** auth, sessions, CSRF,
  and routing (stdlib `ServeMux` method patterns are the house style).
  TLS was excluded while nginx terminated everywhere; that was re-decided
  on 2026-08-31 for proxyless deployments — `RunTLS` in `tls.go`.
- **API stability is the product.** Consumers import this
  module; once they do, a breaking change to an exported signature requires
  flagging every consumer first. Prefer small boring functions (`Run`,
  `ClientIP`, `WriteJSON`) over option structs and types that invite churn.
- **Client IP:** the only correct reading of `X-Forwarded-For` is the
  rightmost untrusted hop, checked against a CIDR trust list. Never accept a
  leftmost-hop variant, even when porting from a project that has one — two
  surveyed projects got this wrong and the bug is spoofable rate-limit and
  login-throttle bypass.
- **Local development against a consumer** uses a `go.work` in the consumer's
  directory, never a `replace` in its `go.mod` (`replace` travels into deploy
  builds where the path is wrong). `go.work` is git-ignored here for the same
  reason.

## Current state

The whole first-release scope from `PROPOSAL.md` is extracted, one file
per concern, tests alongside:

- `lifecycle.go` — `NewServer` (house timeouts), `Run` (variadic; signals,
  bounded drain; a server with a `TLSConfig` serves TLS from it)
- `assets.go` — `Assets` (embedded, hash at startup) and `DirAssets`
  (disk, re-hash on change): per-file fingerprinting, immutable/3600
  handler; registers the missing woff/woff2 mime types
- `cache.go` — `NoCache`, `NoCachePrivate`, `NoStore`, `ETagMatch`
- `clientip.go` — `ParseTrustedProxies` (CIDRs and bare addresses),
  `TrustPrivateProxies`, `ProxyTrust.ClientIP`
- `ratelimit.go` — `NewLimiter`, `Limiter.Allow`; the three annotated
  source copies get retired on next touch of each project
- `faillimit.go` — `FailLimiter` (auth-failure lockout: `Blocked` before
  the credential compare, `Fail`/`Pass` after; extracted from ownvault)
- `render.go` — `ParseTemplates` (base.html layout, or standalone pages
  without one), `Templates.Render` (explicit status)/`RenderPartial`
- `json.go` — `WriteJSON` (marshal-first), `WriteJSONIndent`,
  `JSONError`, `ReadJSON` (per-endpoint cap, pass `MaxJSONBody` by
  default)
- `form.go` — `ReadForm` (capped form parse, multipart-aware)
- `writebudget.go` — `WriteBudget`, per-write deadlines for streaming
  handlers (pairs with `WriteTimeout = 0`)
- `env.go` — `EnvOr`, `EnvInt`, `EnvFloat`, `EnvBool`, `EnvDuration`
- `middleware.go` — `SecureHeaders` (`DefaultCSP`,
  `DefaultPermissionsPolicy`; both overridable per app), `AccessLog`,
  `HSTS`
- `health.go` — `Healthz`, `HealthProbe`
- `tls.go` — `RunTLS` and the `ACME` config, for servers that terminate
  their own TLS instead of sitting behind a proxy; wildcard entries in
  `ACME.Hosts` are issued via DNS-01
- `dns.go` — `DNSSolver` interface and the `Route53` solver (no AWS SDK;
  `sigv4.go` signs its two API calls)
- `dnscert.go` — the DNS-01 wildcard certificate manager behind `RunTLS`
  (unexported; autocert cannot issue wildcards)

Nothing is tagged yet: per the adoption rule, a new project uses the
module first and shakes out the API before v0.1.0. Every extraction has a
rationale entry in `DESIGN-DECISIONS.md`; read it before changing any
exported signature.
