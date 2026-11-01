# Surface and trust-boundary map

Two artifacts come out of recon: **where a model can be made to run**, and
**where the server trusts something the client controls**. A surface list alone
produces guesswork; a sink list alone produces blind payloads. Build both.

## 1. Acquire the artifacts

Record for each: absolute path, version string, SHA-256, install source, update
channel, signature state. Keep the extracted tree immutable; re-extract rather
than edit.

| Class | What to pull |
|---|---|
| Desktop shell | app bundle, ASAR/zip, main and renderer bundles, preload scripts, workers, native modules, splashes |
| Native app | binary, resources, embedded web assets, plist/ini, local databases |
| Managed app | assemblies, resources, embedded config, appsettings |
| Web app | HTML entry, script manifest, every chunk reachable from the entry, source maps, service worker |
| Mobile | APK/IPA, dex/classes, assets, manifest, network security config |
| Extension | manifest, background/service worker, content scripts, bundled deps |
| CLI/daemon | binary or script, config dir, logs, local socket path |
| Relay/sidecar | binary, protocol framing, tool registry, allowlist |

## 2. Static enumeration — six fact classes

Save file:line for every hit.

**Hosts and transports.** absolute URLs, bare hosts, `wss?://`, gRPC service
names, regional and canary variants, `localhost`/`127.0.0.1` daemons, custom URL
schemes and deep links, proxy/relay config and allowlists, certificate pinning
config (a pin list reveals the real upstream host).

**API vocabulary.** `/api/vN/<verb>` literals, RPC method names, socket message
types, request builders (which fields are always sent vs optional), error-code
tables and their UI mapping, retry predicates (which errors are considered
transient — a pacing hint), feature-flag keys and defaults, version negotiation.

**Model intelligence.** model tables (id, provider, context, max output, price,
capability flags, plan gates), routing tables and fallbacks, prompt templates,
system prompts, tool descriptions, output schemas, "is this enabled" checks and
the order they run in.

**Credentials.** mint calls (name, request fields, response shape, TTL), header
construction (which cookies/headers must travel together), storage location, refresh
loops, signing keys baked into the client (search for base64 blobs near `verify`).

**Sinks.** next section.

**Dead weight.** Deprecated verbs still referenced, test/debug flags, admin
namespaces, `x-` header overrides, "internal" endpoints called from the client
but gated by a flag.

## 3. Sink taxonomy

`scripts/bundle_scan.py` implements this pass; the table is what it looks for.

| Sink class | Pattern to find | Why it matters |
|---|---|---|
| URL construction | template literal into `fetch`/`axios`/`URL`, path concatenation | path/param injection, IDOR, traversal |
| Client-driven dispatch | model id, `provider`, `route`, `tier` read from request and used in a lookup | premium model on a free plan, arbitrary backend |
| Object lookup | `get(id)`, `findById`, `where({id})` with a client id and no owner predicate | BOLA/IDOR |
| Entitlement gate | plan/credit/quota checks, `canUse`, `remaining` | order bugs: gate after dispatch |
| Credit write | counter increment/decrement, `usage`, `credit`, `balance` | double-spend, race, negative counts |
| Token mint | `sign(`, `jwt.sign`, `issue`, `exchange` | broad audience, derivation, TTL |
| Token verify | `jwt.verify`, `decode`, key lookup by `kid`/`jku` | alg confusion, missing pinning |
| URL fetch | `fetch(userUrl)`, link preview, OG scraper, webhook, connector | SSRF, internal admin, cloud metadata |
| File read | `readFile`, `sendFile`, path join with client value | traversal, LFI, prompt-file read |
| Extraction | OCR/transcribe/parse-import jobs | separate budget, unmetered model work |
| Process exec | `exec`, `spawn`, `child_process` | command injection reaches the host |
| Deserialize | `JSON.parse` of a client blob used as state, `unserialize`, `yaml.load` | client-trusted state, signature gaps |
| Template | template engines, `%s` into SQL/HTML/shell | injection to another sink |
| Prompt assembly | string concat of user fields into `system`/`messages`, tool description builders | prompt sinks: steer fixed tasks, strip persona |
| Tool passthrough | schema forwarded to provider, `tools:`, allowlist | dropped calls, injected tools |

For each hit record: `{sink_class, file, line, function, client_controlled_param,
validation_seen (y/n), evidence}`. A sink with no visible validation on the
client is a *candidate*, not a bug — the server decides.

## 4. Edges: source → sink

Join the two lists. For every request builder, walk each field to its sink; for
every sink, ask which builder feeds it. The edge is the hypothesis:

```text
spaceId (body)        -> object lookup -> owner predicate?           -> A1/A2
model (body)          -> model resolution -> plan check?             -> E1
plan (body, optional) -> entitlement gate -> default when absent?     -> C3
fileUrl (body)        -> fetch          -> allowlist?                -> G1
title (body)          -> prompt assembly -> escaping/role boundary?  -> E3/P1
clientVersion (hdr)   -> routing branch -> gate skipped on legacy?   -> F1
```

Anything reachable only from a debug flag, a canary host, or an older installer is
still a real edge — those branches are where gates go missing.

## 5. Runtime capture

Attach to the real UI and reproduce one visible AI action.

- Full request and response: headers, cookies, body, ordering.
- Transport: XHR/fetch, WebSocket frames, SSE/NDJSON, RPC.
- What the client does after the response (poll, subscribe, local store edit) —
  a second call is often the one that carries the real payload.
- Diff runtime against the static builder: fields that appear only at runtime are
  server-derived, and are frequently the interesting ones.

Prefer passive observation; script interaction only when the passive capture
cannot reach the surface, and keep the script idempotent.

## 6. Alternate clients

Web prod, web canary, desktop stable, desktop beta, mobile, tablet layout,
extension, CLI, MCP host, relay daemon, legacy installer on disk, regional
mirror. For each: which AI verbs does it know, which does the server still
accept, and is its gating weaker? A verb missing from one bundle is often live in
another.

## 7. Sockets and local protocol surfaces

Framing (length prefix, delimiter, Engine.IO-style packets), handshake/auth/
keepalive/teardown, the complete method list including methods the UI never
calls, and behaviour on unknown methods (empty ACK vs typed error vs close) —
that difference separates "no such capability" from "not authorized". Note
whether the socket returns model output directly or only writes it into a product
object.

## 8. Deliverables

`surface.json` — one row per observation:

```json
{
  "surface": "feature-name",
  "verb": "/api/v3/example",
  "transport": "http|ws|rpc|local",
  "auth": "cookie|bearer|none|minted",
  "status_observed": [200, 400, 402],
  "originality": "unchecked|provider-original:<family>|env-aware:<family>|wrapper|<target>-persona|unknown-backend",
  "sinks": ["dispatch:model", "gate:entitlement"],
  "evidence": "captures/2026-01-01T1200_example.json",
  "source": "bundle/chunk-123.js:45",
  "notes": "spaceId required; 400 masks quota when a cookie is missing"
}
```

`originality` comes from the triage probe: `provider-original` requires both the
vendor answer and a clean environment answer. `env-aware` ranks as a wrapper.

Rank rows by `provider-original? x reaches a model? x selectable? x unmetered? x
steerable?`, then by the presence of a `client-controlled -> gate` sink edge.
The top row is the first experiment.
