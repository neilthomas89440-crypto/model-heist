# Auth and entitlement

Two maps, not one. Authentication answers "who", entitlement answers "what may this
who do". Bugs live in the gap: a valid token with the wrong scope, a gate evaluated on
a value the client controls, a meter written on a path the gate skipped.

## Credential map

For every endpoint that mints something, record:

| Field | Question | How |
|---|---|---|
| audience | what is this token *for*? | decode JWT locally, do not trust the client's label |
| scope | which upstream accepts it, for which verbs? | replay with the smallest possible request |
| lifetime | TTL, refresh path, revocation | wait it out once; refresh once; revoke once |
| replay | does the provider accept it directly? | clean process, no product headers, no client UA |
| confusion | wrong audience/issuer/alg accepted? | alg swap, `none`, cross-env token (prod/canary) |
| derivation | does it embed tenant/plan the server trusts? | compare two accounts' tokens field by field |

Replay is the highest-value test in the skill. A token minted for "comment
suggestions" often carries a broad grant, and that is L3→L4 in one request.

```bash
python ~/.agents/skills/model-heist/scripts/heist.py send \
  --base https://api.provider.example --path /v1/chat/completions \
  --headers '{"authorization":"Bearer <minted>","x-client":"clean"}' \
  --body '{"model":"<id>","messages":[{"role":"user","content":"who made you"}]}'
```

If the provider answers: the target is now just a credential faucet, and the rest is
engineering — mint per request, never persist, never log.

## Token handling checks

- **Signature not verified** — flip one byte in the payload, resign nothing; if the
  server still accepts, done.
- **Algorithm confusion** — `alg:none`, `HS256` with the public key as HMAC secret.
- **Claim trust** — `plan`, `tier`, `isPaid`, `features[]` read from the token rather
  than re-derived server-side.
- **Weak secret** — only with a local copy of the verifier; never against a live
  third-party service.
- **Long-lived refresh** — refresh tokens that survive logout are a persistence path,
  not a bypass.
- **Cookie completeness** — a request that fails only in your client is usually a
  missing cookie, header ordering, or a CSRF token that is bound to a session you
  did not copy.

## Entitlement order

Write down, per AI endpoint, the ordered list of gates it passes:

```text
1. auth (who)
2. plan/tier check        <- which field?
3. credit/quota check     <- which counter?
4. model allowlist        <- which table?
5. dispatch
6. meter write
```

Then ask, one at a time:

- Can the request skip a step by omitting the field the step reads? (defaults are gates
  nobody wrote)
- Does step 4 read the same value step 5 uses? (mismatch = free premium)
- Does step 6 always run, including on streamed aborts, retries, and cached responses?
- Is a *different verb* for the same feature gated by a different subset?

That last one is the unmetered-channel hunt in miniature: the product usually has
several AI verbs (suggest, summarize, title, translate, classify, embed) and they do
not share a gate implementation.

## Meter map

Model the bill before dodging it:

| Question | Method |
|---|---|
| which counter moves on which call? | read usage immediately before/after one call |
| what scope? | two accounts, one workspace; then two workspaces |
| synchronous or lagged? | sample at 0 s / 5 s / 60 s |
| what resets it? | lifetime, daily, monthly, new entity, re-login |
| does a rejected call bill? | one 400 + one 402, then read the counter |
| does a retry double-bill? | same request twice, compare |
| does a stream abort bill? | open, cancel after the first token |

`heist.py meter --n 5 --usage-url ...` reports the payload digest before/after; an
identical digest is either "no counter on this surface" or "lagged" — sample again.

State the honest ceiling:

```text
refill path x entities x turns per entity
```

Anything you cannot refill is a countdown, not a channel. Do not call it L4.

## Gate order to attack first

1. `dispatch` reads a different value than `allowlist` — model-id trust (class N).
2. `meter` is written after the response is returned, so an aborted or cancelled call
   skips it (class I).
3. `plan` is checked in the UI and again in the API, but the API check reads a
   client-supplied tier (class C).
4. A legacy verb has only step 1 (class F).
5. A helper feature has no step 2 or 3 at all (class L).