# Design decisions

Decisions made before any code exists, from the 2026-08-30 survey and naming
discussion. For the full survey data and defect list, see
[PROPOSAL.md](PROPOSAL.md).

## The name is nitrokit; nitro is reserved

Decided 2026-08-30. `nitro` names the future generic web server, which gets
its own fresh directory when work starts. This module is the kit of parts that
server is built from, so it is `nitrokit`. Rejected alternatives: chassis
(best metaphor, but the link to nitro is invisible), nitrous, octane.

Consequence: never grow nitrokit into the server. When server-shaped features
appear (routing conventions, app scaffolding, config files), they belong in
nitro, importing nitrokit.

## Composable functions, not a framework

The model is `github.com/hammondus/mailer`: one zero-dependency module,
small enough to read in a sitting. Each consuming project keeps its own
`main` and takes only the pieces it needs. There is no `nitrokit.App`, no
required initialisation order, and no piece that only works with another
piece.

Why: the seventeen surveyed servers are all hand-rolled stdlib. A framework
would force a migration; a bag of functions can be adopted one concern at a
time on next touch.

## The API surface starts small and boring

Once ten projects import the module, its API is a contract — the workspace
rules for shared modules then require flagging every consumer before a
breaking change. So the first release exposes functions whose signatures
won't change (`Run`, `ClientIP`, `WriteJSON`), not an options-struct `Server`
type that invites churn. Each piece in scope survived five or more
independent reimplementations without its shape changing, which is the
evidence the contract is stable.

## Auth, sessions, and CSRF are out of scope

The five existing implementations genuinely differ: SQLite sessions,
in-memory maps, JSON files, PBKDF2 versus Argon2id, one CSRF scheme. Forcing
one shape now means designing an auth library — a different, riskier project.
Revisit only if the shapes converge, the way `mfa` was extracted. Do not fold
auth in without a fresh decision.

Also out:

- **Routing.** Stdlib `ServeMux` with Go 1.22 method patterns is already the
  house style and needs no wrapper.
- ~~**TLS.** nginx terminates everywhere.~~ Re-decided 2026-08-31 — see
  [TLS is in scope](#tls-is-in-scope-autocert-is-the-one-dependency).

## Client IP walks X-Forwarded-For from the right

The module ships one implementation: rightmost untrusted hop, with a CIDR
trust list for the proxies in front. The survey found two spoofable
leftmost-hop variants gating rate limiting and login throttling. The
leftmost value is client-controlled and must never be trusted.

Extracted 2026-08-31 as a near-verbatim port of the strongest surveyed
copy. Choices that carry over:

- `netip.Addr` in and out, not strings: unmapping IPv4-mapped IPv6 and
  stripping zones happen once, and the result is a valid map key for
  rate-limit buckets.
- A bare address in the trust list is an error, not an implied /32. The
  strictness came over from the source, kept because a config typo should
  fail at startup rather than silently widen or narrow trust.
- A malformed hop returns the peer: nothing left of garbage can be
  believed.
- The zero `ProxyTrust` trusts no one, so the unconfigured state is the
  secure state. One surveyed project's implicit "loopback and RFC 1918 are
  trusted" heuristic was considered and rejected as a default — it is
  exactly the kind of invisible trust decision the survey caught going
  wrong.

## Adoption is on next touch, never bulk retrofit

New projects adopt first, so real use shakes out the API before anything
imports a tagged version. Existing projects fold in when next touched.
Production projects move on their own schedule, one concern at a time.

## Distribution follows mailer

`github.com/hammondus/nitrokit` if it resolves; otherwise a per-project
`go.work` listing `.` and the path to nitrokit — git-ignored and kept out of
the Docker build context. Never a `replace` in `go.mod`: `replace` travels
into the deploy build, where the relative path is wrong. And never put a
`go.work` at a workspace root above sibling modules: every `go` command
beneath it picks it up, and the modules it does not list stop building.

## Lifecycle: Run owns the signals; the drain budget is fixed

Decided 2026-08-31, with the first extraction. `Run(ctx, srv)` installs its
own SIGINT/SIGTERM handler by wrapping ctx with `signal.NotifyContext`, so
a project with no shutdown at all is fixed by one line:
`nitrokit.Run(context.Background(), srv)`. The ctx parameter exists for
programmatic stops and tests, not because callers are expected to wire
signals themselves.

The shape is a composite of the two strongest surveyed copies:

- From one copy: the error-channel idiom that surfaces a failed listen
  immediately instead of blocking on a signal that never comes.
- From another: restore the default signal disposition before the
  drain, so a second signal force-quits a stuck shutdown, and return the
  listener's error after the drain rather than dropping it.

Rejected: a third copy's `srv.Close()` on signal. It looks like shutdown but
drops in-flight requests — the exact defect the module exists to fix.

The 10-second drain budget is a constant, not a parameter. Every surveyed
copy that drains uses 10 s, and the budget is coupled to the supervisor's
kill timeout (docker stop defaults to SIGKILL after 10 s) — a project that
changes one must change both, which a Run parameter would hide.

`Run` returns nil after a clean drain; `http.ErrServerClosed` never escapes.
A drain that runs out of time returns a `shutdown:`-wrapped error, because
it means connections were cut mid-request and main should say so.

nitrokit does not log. The surveyed mains split between `log` and `slog`;
a library line in the wrong format is noise in half the consumers. The
caller logs "listening" before `Run` and "shutdown complete" after it.

## House timeouts are 5/15/30/60

Decided 2026-08-31. `NewServer` sets `ReadHeaderTimeout` 5 s, `ReadTimeout`
15 s, `WriteTimeout` 30 s, `IdleTimeout` 60 s — the strongest surveyed set.
The survey's values cluster around two variants; the differences that
matter:

- `WriteTimeout` 30 s rather than the other variant's 15 s: a
  handler that calls an upstream service synchronously (SMTP with a 10 s
  dial budget) must be able to return a real answer.
- No SSE accommodation in the defaults. The surveyed streaming servers show
  the correct pattern — `WriteTimeout` 0 plus a per-write deadline — and
  they get it by overriding the field on the returned `*http.Server`, which
  is why `NewServer` returns the plain struct instead of hiding it.

## Assets: per-file ?v= hashes, immutable only on an exact match

Decided 2026-08-31, with the second extraction. `Assets` is the strongest
of the eight surveyed copies:

- **Per-file hashes, not one bundle hash.** One copy hashes the whole tree
  into one version, so editing one file evicts every cached asset.
  Per-file hashes keep untouched files cached across deploys.
- **`?v=` query, not `name.<hash>.ext` paths.** Both appear in
  the survey; `?v=` is the majority form, needs no filename rewriting, and
  keeps the unversioned path servable for bookmarks and favicons.
- **`immutable` only when `?v=` equals the file's current hash.**
  One surveyed copy marks any non-empty `?v=` immutable, which claims "this
  URL names these bytes" for a URL that names different bytes. The
  mismatch is harmless in practice but the exact check costs nothing.
- **Per-file ETag plus `http.ServeContent`**, so the one-hour tier
  revalidates instead of re-transferring, and range and HEAD requests work.
- **A missing name renders the plain unversioned path** (also a surveyed
  behaviour): the typo becomes a visible 404 in the page instead of
  a versioned URL that never existed. Not a startup error, because the
  template func has no way to fail a page that renders lazily.

`NewAssets` hashes once at startup, which is correct only for embedded
files. The doc comment says so; a disk-serving variant would need
per-request hashing and is not worth building until a consumer needs it.

## Cache policy is three helpers and ETagMatch

`NoCache`, `NoCachePrivate`, and `NoStore` are one Set call each. They
exist so the house policy has one named form per tier — HTML,
authenticated HTML, secret-shown-once — instead of a string literal that
drifts. `ETagMatch` is a copy found byte-identical in four surveyed
projects, promoted to the module.

## Rate limiter: the third copy's extraction note, honoured

Extracted 2026-08-31 from the original of the three annotated copies —
each fork carried a comment saying "extract this to a module instead of
editing three copies". Kept: string keys (per-IP and
per-API-key limits are the same limiter), the injectable clock, and the
sweep-on-Allow design that needs no background goroutine.

Two deliberate changes from the sources:

- **Eviction waits for a full refill.** The copies disagreed on the idle
  threshold (10 versus 30 minutes) while sharing the same justifying
  comment: "idle long enough to have refilled anyway". A constant breaks
  that justification for slow buckets — eviction grants a fresh burst on
  the key's next request, so dropping a 1-token-per-hour bucket after 10
  minutes hands out tokens early. The threshold is now
  `max(10min, burst/rate)`, which is what the comment always claimed.
- **`NewLimiter` panics on `rate <= 0` or `burst < 1`.** Either configures
  a limiter that can never issue a token, and `rate <= 0` divides by zero
  in the retry-after calculation. Both are startup mistakes; failing at
  the constructor beats failing per request.

The three source copies are to be retired on next touch of each project,
per the adoption rule.

## Render is a composite: one copy's parse, another's execute

Extracted 2026-08-31. No single copy was strongest end to end. One copy
has the best parse — one set per page via `base.Clone()`, partials
(`_*.html`) parsed into every page and into a standalone set for htmx
fragments — but writes templates straight to the ResponseWriter, so a
mid-render failure is a 200 with half a page. Another buffers, hashes the
buffer into a strong ETag, and answers If-None-Match — but bundles the
security headers into render, which belong in `SecureHeaders`.

`Render` returns an error instead of logging and writing a 500 itself
(the no-logging rule): a non-nil error guarantees nothing was written, so
the caller logs it and calls `http.Error`. The file-name conventions
(`base.html` layout, `_` partial prefix) are the house convention from
the six surveyed copies, not an invention.

`Vary: Cookie` is set unconditionally, from the same source: house pages
are mostly session-cookied, a cache that keys only on the URL can hand one
user's stored page to another, and on a cookieless site the header is
harmless.

## Helper decisions worth a line each

- **JSON** (2026-08-31): the strongest of five surveyed
  signatures — 1 MiB `MaxBytesReader`, `DisallowUnknownFields`, and the
  Content-Type check that doubles as CSRF protection. `WriteJSON` marks
  responses no-store.
- **env** (2026-08-31): the error-returning shape over a surveyed
  warn-and-fall-back variant — the library does not log, and a
  config typo should stop startup, not silently run on defaults. Dropped
  the source's "duration must be positive" check: an app constraint, not a
  parsing one.
- **AccessLog** takes `*slog.Logger` explicitly — the one exception to
  "nitrokit does not log", because logging is this function's entire job,
  and the explicit parameter keeps the format the consumer's choice. The
  recorder adds `Unwrap`, so `http.ResponseController` flushing (SSE)
  works through the middleware — the surveyed twenty-liners all silently
  break it.
- **SecureHeaders** is a copy found byte-identical in two projects,
  with the CSP as a parameter; empty means `DefaultCSP` (that
  policy, verbatim). The Referrer-Policy comment about `same-origin`
  versus `no-referrer` records a production breakage and travels with the
  code.
- **Healthz / HealthProbe** (the surveyed probe): the probe dials loopback
  on the listen address's port, because the configured host may be a
  wildcard bind.

## TLS is in scope; autocert is the one dependency

Re-decided 2026-08-31. The original exclusion rested on one premise —
"nginx terminates everywhere" — and that premise is ending: nitro will
run outside nginx proxy manager and must terminate its own TLS. TLS
termination is lifecycle infrastructure, kit-shaped like `Run`, so it
lands here and not in nitro.

This is the first `require` in `go.mod`:
`golang.org/x/crypto/acme/autocert`. The zero-dependency rule survives as
"stdlib plus x/crypto, nothing else", for these reasons:

- The alternatives are worse. Hand-rolling an ACME client is
  security-sensitive protocol code that should not be written here.
  File-based certificates with an external certbot renewal cron preserve
  zero-dep but rebuild what the proxy already did, with more moving parts
  in every deployment.
- x/crypto is maintained by the Go team and is the closest thing to
  stdlib that is not stdlib.

Shape decisions:

- **`RunTLS(ctx, srv, ACME{...})`, parallel to `Run`.** The autocert
  types stay out of the exported API, so consumers import only nitrokit.
- **`Run` and `RunTLS` share one lifecycle** (`runAll`): RunTLS's second
  server — ACME HTTP-01 challenges plus the HTTPS redirect on port 80 —
  drains under the same signal handling and the same 10 s budget, with
  the shutdowns concurrent so one slow drain cannot starve the other's.
- **`ACME.CacheDir` is required, not optional.** Without persistence
  every restart requests fresh certificates, and Let's Encrypt's rate
  limits turn a few redeploys into an outage. Refusing to start beats
  discovering that in production.
- **Port 80 is hardcoded.** HTTP-01 is defined on port 80; a parameter
  would only exist for tests, which override the unexported variable
  instead.
- **HSTS is a separate middleware, not part of `SecureHeaders`.** Every
  proxied consumer uses SecureHeaders today, and the TLS terminator owns
  the transport policy — folding HSTS in would have every app behind
  nginx proxy manager suddenly publishing it. `HSTS` is one year, no
  includeSubDomains, no preload: both widen the promise to hosts the
  server may not control, and neither is easy to walk back.
- **Calling `RunTLS` accepts the CA's terms of service**
  (`autocert.AcceptTOS`). There is no prompt to answer in a server that
  starts from systemd or Docker; the doc comment says so instead.

One operational note found while testing: `Shutdown` reaps a connection
that was opened but never sent a request only after 5 seconds (Go issue
22682), so a drain can take 5 s even with no work in flight. The 10 s
budget absorbs it; do not shrink the budget below that.

## Wildcards: DNS-01 with a solver interface and a hand-rolled SigV4

Decided 2026-08-31, same day as the TLS re-decision, because the need is
not speculative: a public wildcard on Route 53 is already in production,
and nitro inherits it.

autocert does not implement DNS-01, so wildcards get their own machinery:

- **`DNSSolver` is a two-method interface** (`SetTXT`, `CleanupTXT`).
  nitrokit ships `Route53`; any other provider is implemented by the
  consuming project, so a provider SDK never lands in the shared module.
  Waiting for propagation is the solver's contract — it is
  provider-specific (Route 53 exposes it as `GetChange` INSYNC), and the
  manager cannot know how.
- **The Route 53 solver signs with an in-module SigV4, no AWS SDK.**
  Every alternative (lego, libdns, the SDK directly) drags the AWS SDK
  tree into `go.mod`. The signer covers exactly the two operations the
  solver makes, and a signing bug fails closed — AWS rejects the request
  — so owning it risks an alarm, not a hole. The test vector is AWS's
  documented example, reproduced with an independent Python
  implementation before being pinned in the Go test. Credentials come
  from the standard AWS env vars only (session token included); there is
  no `~/.aws` parsing. Scope the IAM policy to
  `route53:ChangeResourceRecordSets` on the one zone plus
  `route53:GetChange`.
- **The renew loop is the only issuer.** DNS-01 waits on propagation and
  takes minutes; no TLS handshake survives that, so `GetCertificate`
  never obtains inline (autocert's in-handshake issuance works only
  because HTTP-01 is fast). Consequence: on a first-ever deploy,
  handshakes for wildcard names fail until the background issuance
  completes, visibly, in `ErrorLog`.
- **Renewal failures are logged** — through `srv.ErrorLog` when set,
  otherwise the standard logger, mirroring `http.Server`'s own
  convention. This extends the AccessLog logging exception: a failed
  renewal has no request to fail, and silence here is an outage 30 to 60
  days later.
- **Authorizations are solved sequentially**, one TXT record live at a
  time. An order covering apex plus wildcard puts two challenges at the
  same `_acme-challenge` name, and an UPSERT-based solver would overwrite
  one with the other if they ran together.
- **A wildcard entry does not cover its apex.** List `example.com`
  separately; it validates over HTTP-01 through autocert like any exact
  host. This is certificate matching reality, not a module choice.
- **The manager shares autocert's account key file**
  (`acme_account+key`, same PEM format), so both paths present one CA
  account.
- **Tests run against an in-repo fake ACME server**, not pebble —
  pebble would be a test-only `require`, and the fake needs only RFC
  8555's happy path with JWS payloads decoded unverified, because the
  code under test is this module's orchestration, not the protocol.

## First extraction order

Lifecycle, assets, and client IP first — they cover the worst survey gaps
(six projects with no timeouts or shutdown, and the spoofable IP variants).
Then the rate limiter, retiring the three annotated copies.

## Run is variadic; a TLSConfig means TLS

Decided 2026-09-01, from the first adoption pass against ownvault, which
runs a plain listener plus an mkcert file-certificate listener for LAN
PWA testing — a pair `Run(ctx, srv)` could not serve and `RunTLS`
(ACME-only) does not cover. Three shapes were considered:

- Exporting the internal pair type (`RunServers(ctx, ...ServerStart)`,
  each entry a server plus its start function). Rejected: it exports
  plumbing, and every caller writes the same two start functions.
- A separate `RunTLSFiles(ctx, srv, cert, key)`. Rejected: it only
  handles one server, so the pair still needs a combinator.
- `Run(ctx, servers ...*http.Server)`, serving any server whose
  `TLSConfig` is non-nil with `ListenAndServeTLS("", "")`. Chosen: the
  signal is not invented — it is exactly how `http.Server` itself decides
  where certificates come from, and `RunTLS` already worked this way
  internally. Loading cert files into a `tls.Config` is two lines of
  stdlib in the caller, so no file-path parameters are needed.

Existing single-server calls compile unchanged. `Run` with no servers is
an error, not a silent return: a caller that computed an empty list has a
bug. The internal `runAll` keeps injectable start functions — that is
what the listener-failure tests stub — and `RunTLS` now delegates to
`Run` for its own pair.

The drain interaction with server-sent events is documented rather than
solved: an open stream is an in-flight request, so it holds every stop
for the full 10 s budget unless the app closes its streams from
`RegisterOnShutdown`. A lifecycle-owned hook was rejected — which
connections are streams and how to end them is app knowledge.

## SecureHeaders takes the Permissions-Policy as a parameter

Decided 2026-09-01. The policy was hardcoded with `camera=()`, which
denies `getUserMedia` to the page itself — and ownvault scans QR codes
in-page (vault setup codes and 2FA enrolment), so the one header meant as
pure hardening broke a feature. The CSP was already a parameter for
exactly this reason; the Permissions-Policy now follows the same shape:
a parameter, empty means `DefaultPermissionsPolicy` (the previous
hardcoded value, unchanged). Two positional strings is the accepted cost
of staying an options-struct-free function; the CSP comes first because
it is the one more often customised.

## ReadJSON's body cap is a call-site parameter

Decided 2026-09-01. The 1 MiB constant was sized from the survey, and the
first adoption pass found the counterexample: ownvault's `/api/push`
accepts up to 8 MiB (a full-vault restore). A budget is a property of the
endpoint, not the module, so `ReadJSON` now takes `maxBytes` explicitly.
No default parameter value and no second function: the explicit number at
every call site is the point — each endpoint's budget is visible where a
reviewer reads the handler. `MaxJSONBody` (the old 1 MiB) is exported as
the value to pass when nothing bigger is justified.

`DisallowUnknownFields` stays unconditional. Note for consumers whose
clients and servers can skew in version (ownvault's browser extension
talks to arbitrary servers): a newer client's unknown field is a 400
here, so such wire formats should keep their own tolerant decode instead
of adopting ReadJSON.

## Auth-failure lockout is in scope as FailLimiter

Decided 2026-09-01, extracted from ownvault's `failLimiter` (the only
surveyed copy, but the shape is generic to any token or login endpoint
and nitro will need it). It is throttling, not auth machinery, so the
auth exclusion does not apply — no credentials, sessions, or storage.

`Limiter` cannot express it: a token bucket charges every request, and
what the pattern needs is to charge only *failures*, clear on success,
and — the property that matters — refuse *before* running the credential
compare, so an over-limit request learns nothing from its guess. Adding a
non-consuming peek to `Limiter` was rejected as bending one abstraction
to fake another.

Kept from the source: the lazy window reset (no background goroutine, the
same design as `Limiter`'s sweep-on-Allow), the sweep-then-evict cap at
4096 keys (losing a counter weakens limiting far less than an unbounded
map weakens the server), and Pass clearing strikes entirely. Changed: the
limit and window are constructor parameters with the constructor panic
convention from `NewLimiter`, and the injectable clock comes over for
tests.

## The 2026-09-01 adoption survey round

A five-agent survey of every project in the workspace mapped each
hand-rolled server against the module and ranked the gaps by how many
conversions they block. The changes below came out of it, made together
while nothing is tagged and only nitro imports the module. The
per-project conversion notes are not published (they describe the private
workspace — see `private/` in CLAUDE.md).

### Render takes a status code and skips validators on non-200

Error and auth pages are pages: surveyed projects render login forms at
401 and 429, error pages at 404, and one writes a status before
rendering. Without a status parameter every one of those becomes a 200 —
wrong to clients and to monitoring — which made the old `Render`
unadoptable by two of the three template-using production projects.
The status is a required positional parameter rather than a
`RenderStatus` variant: the strongest surveyed copies both take one, and
an explicit `http.StatusOK` at ordinary call sites is the boring,
auditable form.

Non-200 renders skip the ETag and the If-None-Match check: a 304 tells
the client its stored copy is still good, which only makes sense for a
page that was good. `Render` also now sets Content-Length from the
buffer and sends headers-only for HEAD (from a surveyed render).

### ParseTemplates works without a base.html

Four surveyed projects have layout-free templates — standalone pages, or
a lone contact form — and the hard base.html requirement locked all of
them out. With no base.html each page is now a standalone
document rendered by its own name, partials still parsed in. base.html
remains the layout convention when present — nothing changes for layout
sites, and a missing base.html is only silent when the pages genuinely
stand alone, in which case it was not a mistake.

### WriteBudget: per-write deadlines for streaming handlers

Seven surveyed projects stream (SSE or websockets) and must zero
`WriteTimeout`, which silently gives up slow-client protection on every
route. nitro already built the fix — a deadline renewed as writes make
progress, nginx's send_timeout semantics — as its `deadlineWriter`;
`WriteBudget(budget, next)` is that code promoted, with the budget as a
parameter and the renew-at-most-once-a-second economy kept. nitro
retires its copy on next touch, per the adoption rule.

### DirAssets: fingerprinting for files that change under the server

`Assets` hashes once at startup, which is documented as wrong for disk
files — and six surveyed projects serve from disk at least some of the
time (dev modes in two; always in the rest, nitro among them).
`DirAssets` checks the file on every URL
call and request: a stat when unchanged (size+mtime cache), a re-hash
when edited, so a saved file gets a new `?v=` URL on the next page
render with no restart. The tree is opened as an `os.Root`, so a
request path cannot escape it. `immutable` on an exact `?v=` match is
still correct for disk files because the hash and the bytes are checked
in the same request.

Also here: an init registering `font/woff2` and `font/woff`, missing
from Go's built-in extension table (found when a surveyed site's webfont
was served as octet-stream).

### WriteJSON marshals before writing the header

One surveyed `writeJSON` was strictly better than the module's:
marshalling first turns an unencodable value into a clean 500 instead of
a committed 200 with no body. Adopted, per that copy's own comment.
`WriteJSON` also now defers to a Cache-Control the handler already set
(the same rule `Render` follows), and `WriteJSONIndent` exists for the
two surveyed endpoints people read raw. The trailing newline stays for
curl ergonomics.

### ReadForm: the capped form parse

Four surveyed projects call `r.ParseForm()` with no body cap at all —
real holes, not just duplication — and one documents being
burned by `ParseForm` silently ignoring a multipart body. `ReadForm`
takes the per-endpoint cap (the ReadJSON convention) and dispatches on
the Content-Type so a form that grows a file input keeps working. The
multipart in-memory threshold is a constant, not a parameter: it tunes
memory, not the cap.

### Re-decided: a bare address is a valid trust-list entry

Reverses part of the 2026-08-31 client-IP decision ("write /32 and mean
it"). Two production deployments already configure
bare proxy addresses, so the strictness had become a silent config break
on conversion, and a bare IP is not actually ambiguous — it names
exactly one address. `ParseTrustedProxies` now reads `172.18.0.2` as
/32 (or /128). Rubbish still fails at startup.

### Re-decided: TrustPrivateProxies, an explicit private-space trust list

The 2026-08-31 decision rejected "loopback and RFC 1918 are trusted" as
a *default*, and that stands — the zero `ProxyTrust` still trusts no
one. But five surveyed projects hand-rolled exactly that heuristic, and
every conversion that forgets to configure CIDRs silently attributes all
traffic to the proxy, collapsing rate-limit buckets — the survey's most
dangerous silent regression. `TrustPrivateProxies()` is the middle
ground: a named constructor covering loopback, RFC 1918, ULA, and
link-local, so the posture is a greppable choice in the caller rather
than invisible magic. Its doc comment says when it is wrong (a server
LAN clients also hit directly).
