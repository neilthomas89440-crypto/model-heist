---
name: autoreg-pools
description: Build a pool of accounts on a target platform and expose them as one OpenAI-compatible endpoint — signup automation, mail and OTP capture, proxy and fingerprint hygiene, key minting, rotation on quota, and honest economics. Use when breadth across accounts is the chosen strategy; not a substitute for breaking the product, and not for third-party or stolen accounts.
metadata:
  version: "1"
---

# Autoreg pools

A pool replaces one limit with N of them. It is a **breadth** strategy: it never proves
the product is broken, and it dies the day the vendor changes signup.

Use it when: the vendor's own client has no unmetered path (see `skill://model-heist`),
the per-account free tier is real, and the user accepts the economics below.
Never when: the accounts are not yours, the quota is per-identity rather than per-account,
or the goal is a clean model route that the product can revoke.

## Economics first

```text
daily_capacity = accounts_working x per_account_quota x survival_factor
account_cost   = captcha + proxy + mail + time
```

Measure `survival_factor` on 10 accounts before scaling: the fraction still answering
after 24 h. A pool with 20% survival and a $0.003 captcha is a tool; a pool with 5%
survival is a hobby. Write these numbers into `docs/POOL.md` before writing the farmer.

## Pipeline

Each stage is independent code with its own failure class — never one monolith:

```text
identity   -> mail address (alias on your own domain, IMAP-readable)
signup     -> HTTP first; browser only for the challenge
verify     -> OTP from IMAP (bounded poll, exact regex)
mint       -> the session/API key the product issues
store      -> accounts.jsonl: {alias, email, password, totp, key, created, state}
probe      -> one real completion; record status + latency + quota error shape
rotate     -> on the quota error the platform actually returns
```

**HTTP first.** A signup that needs a browser is a signup whose challenge you must
solve; a signup that does not is a script. Probe the JSON routes before automating the
UI (`POST /api/auth/sign-up/email`, `POST /auth/register`, `/api/v1/users`). Look for
magic-link flows: they often skip captcha entirely.

**Mail.** Alias on a domain you control (Cloudflare Email Routing, ImprovMX) beats
temp-mail: it survives re-verification and the same inbox serves unlimited aliases.
Temp-mail APIs (`mail.tm`, `1secmail`) are fine for volume but lose the inbox.

**Challenges.** Solve at the cheapest layer that works:
`TURNSTILE → sitekey + page → solver` (local vision model, or a paid API at ~$0.001–0.003).
Reuse a verified clearance when the platform allows it. Never ship a JS injection patch
and call it stealth — see the fingerprint notes.

**Fingerprint hygiene.** One account = one stable identity: same egress IP family, same
user agent, same timezone, same locale, and consistent hardware signals. Changing them
mid-life is what gets accounts linked and banned. Engine-level coherence (a real
Chromium build with a profile) is worth more than any patch script.

**Proxy hygiene.** Residential for signup where datacenter is flagged; sticky sessions
per account, never a shared exit for the whole pool. Record the exit IP per account.
If the platform blocks a region, that is a routing decision, not a bug.

## Rotation

```python
# the only correct trigger: the error the upstream returns
if resp.status == 429 and "quota" in body:      cooldown(acct, 60 * 60)
elif resp.status == 401:                        acct.state = "dead"
elif resp.status == 429:                        cooldown(acct, 5)
```

Sticky per conversation when the platform caches or bills per account. Single-flight
refresh. Reserve: never spend the last working account on a long shot.

## Gateway

One process, `/v1/chat/completions` and `/v1/models`, streaming converted properly,
errors relayed honestly. `scripts/pool_gateway.py` is the minimal working shape:
accounts file → rotation → upstream. Start it, point a client at it, verify one
completion, then scale the pool — not the other way round.

## Verification

Ship the pool when, and only when:

1. 10 accounts created end to end with no manual step;
2. each answers one real completion through the gateway;
3. 24 h later, the survival number is recorded;
4. a quota error on one account rotates to the next without the client noticing;
5. `grep` of logs shows no credential.

## Anti-patterns

- Scaling the farmer before one account works twice in a row.
- One shared proxy for the pool.
- Rotating on a timer instead of on the error.
- Treating a banned account as a schema bug.
- Storing keys in the repo.
- Presenting a pool as "we broke the product".
- Any account that is not yours.