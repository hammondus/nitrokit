# Roadmap

Candidate additions that belong at the kit layer, in likely order.
Each becomes a `private/DESIGN-DECISIONS.md` entry when work starts; nothing here
is committed to until a consumer needs it.

## Compression middleware

Port the mature surveyed gzip middleware (see `private/PROVENANCE.md`
for the source): the compress decision deferred to WriteHeader, a
content-type allowlist, Content-Length dropped, `Vary: Accept-Encoding`,
Flush passthrough for streaming. Every surveyed project would benefit.

Design questions to settle at extraction time:

- ETag interaction: compressed bytes differ from identity bytes, which
  is why the source emits weak ETags on compressed responses. `Render` and
  `Assets` emit strong ones — the middleware must weaken or vary them,
  not silently invalidate the revalidation the module already does.
- Compressing already-compressed assets (woff2, png, gzip) wastes CPU;
  the allowlist handles it, keep it.
- brotli would need a dependency; gzip is stdlib. Start gzip-only.

## HTTP/3

The right home is here — it is lifecycle infrastructure, a sibling of
`RunTLS` — but the standard library has no HTTP/3, and the only real
implementation is `quic-go`: a large dependency tree, which breaks the
"stdlib plus x/crypto" rule far harder than autocert did. Taking it is
a design re-decision, not a feature ticket.

Deferred until a deployment actually needs it. Everything currently
sits behind a terminating proxy or serves few clients, where HTTP/3
buys little; revisit if nitro fronts a public site where handshake
latency matters. If adopted: an opt-in `RunTLS` variant so consumers
that skip it never link quic-go.

## encoding/json/v2

Not before it leaves `GOEXPERIMENT`. As of Go 1.27 every file in
`encoding/json/v2` is guarded by `goexperiment.jsonv2`, so importing it
would force every consumer to build with that experiment set — a
build-environment dependency, and an API that can still change.

Revisit when a stable release ships it unguarded. The swap is confined
to `json.go`: `writeJSONBytes` already takes the marshal function, and
`WriteJSON` keeps marshalling to bytes before writing, since v2's
`MarshalWrite` streams and would turn a marshal failure back into a
truncated 200. v1 gains v2's engine on graduation, so performance is
not a reason to move early.

The decision to make then is whether `ReadJSON` adopts v2's stricter
defaults: case-sensitive field matching and duplicate-key rejection.
Both harden a request decoder against parser differentials, and both
are consumer-visible — a client sending `Name` for `name` goes from
accepted to 400, and the error text copied into the 400 body changes.
That is a `private/DESIGN-DECISIONS.md` entry, not a routine edit.

## Previously deferred

The adoption survey's smaller "extract when a third consumer appears"
items are listed at the end of `private/ADOPTION.md` — CORS,
concurrency semaphores, outbound gates, SPA/pre-hashed asset serving,
CSS URL rewriting, large-file range serving.
