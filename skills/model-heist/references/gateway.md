# Gateway contract

Build only after all four gates pass once. A gateway around an unproven route is a
polished dead end.

## Endpoints

| Route | Behaviour |
|---|---|
| `GET /v1/models` | ids the upstream actually serves, from the gateway's own probe cache — never a hardcoded list |
| `POST /v1/chat/completions` | stream (SSE) and non-stream, same semantics |
| `GET /v1/usage` | the target's real counters, relayed; never synthesized |
| `GET /healthz` | upstream reachability, pool size, last error class — no secrets |

Extras that pay for themselves: `POST /v1/messages` (Anthropic shape, for Claude Code),
`POST /v1/responses` (OpenAI Responses), `GET /metrics` (latency and error counts).

## Traffic rules

- **Stream first.** Chat clients use streaming; a gateway that buffers is unusable.
  Convert stream→stream, not stream→complete→stream.
- **Pass upstream errors honestly.** 429 stays 429 with `Retry-After`; 402 stays 402.
  Never turn a quota error into a 200 with an empty body.
- **Timeouts** per phase: connect, first byte, inter-token idle. A hung upstream must
  not hold a client request open forever.
- **Bounded bodies** on both directions; a missing length is not "unlimited".

## Credential lifecycle

- Mint in-process; keep material in memory only.
- Refresh on `401`/expiry with a single-flight lock (one refresh, other requests wait).
- Never write a token to a log, a config file, or a response header.
- On repeated refresh failure, mark the credential dead and rotate — do not retry-loop.

## Entity pool

- Rotate on the **quota error the target actually returns**, not on a timer.
- Sticky per conversation when the upstream bills or caches per entity.
- Cooldown classes: `429 → seconds`, `quota → minutes`, `401 → dead`.
- Circuit breaker: N consecutive failures of one class → open, then half-open probe.
- Keep a reserve; never spend the last entity on a long shot.

## Pacing

Derive from the measured curve, not from vibes:

```text
success_rate(interval) -> the interval with success >= 99% and the lowest cost
```

Record the curve in `docs/<target>-pacing.md` with the sample counts.

## Registration with the agent runtime

Provide: base URL, a dummy key if the gateway does not authenticate, model ids, and one
verified completion command. Verify by running it — a gateway that "should work" is not
registered.

## Minimal implementation sketch

```text
server.py
  app = FastAPI()
  /v1/chat/completions -> pool.acquire() -> upstream.post(stream=...) -> relay
  /v1/models           -> cache(probe_upstream_models(), ttl=300)
  /v1/usage            -> upstream.get(usage_path)
pool.py    round-robin + cooldown + single-flight refresh
auth.py    mint/refresh, in-memory only
config.py  upstream base, model map, pacing, pool paths
tests/     stub upstream; assert: streaming chunks relayed, 429 relayed, refresh
           single-flighted, no secret in logs
```

Conformance tests that matter: streaming relay, error passthrough, refresh race, pool
rotation on quota, and "no credential in any log line" (grep the log in the test).

## What not to build

- A model list assembled from documentation.
- A fake `tool_calls` rewriter "to make it compatible" — that turns a clean route into
  a wrapper and destroys the Tools gate.
- Token-level streaming emulated by splitting a complete response (breaks tool calls
  and progress).
- Retry storms on a metered route: they are the most expensive bug in the system.
- A dashboard before a working route.