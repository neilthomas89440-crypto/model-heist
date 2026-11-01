# Evidence, queue, and the relentless loop

This file exists because the most expensive failure in a heist is not a wrong
hypothesis. It is stopping between experiments — writing a status report and
waiting for the user to say "continue" while the queue still had runnable work.
The second most expensive is a finding that only ever existed in chat.

## Repo first

If the project already ships a map, obey it before this file:

| File | What it tells you |
|---|---|
| `README.md` (repo root) | what the project is, where each thing lives, session read order |
| `docs/INDEX.md` | every document, generated — if a doc is missing here, regenerate |
| `docs/PROTOCOL.md` | that project's naming, templates, redaction, stop rules |
| `reverse/<target>/README.md` | target status board and where its evidence lives |

Do not create a second layout beside an existing one. Extend what is there; when the project has a
generator (`python tools/gen_index.py`), run it after every document you add.

## Artifacts

| File | Content | Updated |
|---|---|---|
| `docs/INDEX.md` | generated map of every document | after any doc add/rename/archive (run the generator) |
| `docs/QUEUE.md` | mission contract, Now/Next/Closed, refill log | every experiment start/end |
| `docs/LEDGER.md` | one row per probe, negatives included, append-only | every probe |
| `docs/BUGS.md` | bug register: id, class, source→sink→boundary, severity, level unlocked, status | every confirmed bug |
| `docs/INVENTORY.md` | builds, hashes, artifacts, entities, gateways | new build/entity/gateway |
| `docs/findings/YYYY-MM-DD-<surface>.md` | raw probe record: request shape, status, excerpt, hash, observation/inference/unknown, verdict | every probe with an observable |
| `docs/<topic>.md` | curated conclusion per mechanism class, citing finding ids | when a conclusion changes |
| `README.md` | protocol map, current level, findings index | new surface or level change |

Rules: append, never overwrite — corrections are a new record with
`supersedes:`; observation, inference, and unknown on separate lines; no token,
cookie, or third-party PII in `docs/` (hash it, keep the live value in a
gitignored `state/`); a claim without an evidence id, capture path, or hash is
labelled `unverified`; a doc whose build id moved is marked `stale` and
re-verified before citation.

**Probe → record → next probe.** A turn that produces a finding and no file is a
violation; a "documentation detour" that replaces the next queued experiment is
the same violation wearing a lanyard.

## Mission contract and queue

```markdown
# Queue

TARGET:        <product the user named>
CHANNEL:       text | audio | image | code | any
ACCEPT:        provider-original AND no product/tenant metadata visible
REJECT:        product persona, jailbreak-only, BYOK, payment, account farm,
               third-party tenants
ENTITY BUDGET: <accounts> x <credits>; reserve <n>
WORKING NOW:   <surface> -> L<level> -> <evidence id>
UPDATED:       <ISO-8601>

## Now
| id | claim | source -> sink -> boundary | test (one variable) | predicted observable | falsifier | cost | status |

## Next
| id | claim | source -> sink | test | predicted observable | falsifier | cost |

## Closed
| id | verdict | evidence |

## Refill log
| at | classes used | new ids |
```

- `Now` holds exactly one experiment; `Next` holds at least two.
- Every experiment states a predicted observable and a falsifier *before* it runs.
  "Try it and see" is not an experiment.
- After a result: finding record, ledger row, move the row to `Closed`, promote
  the next, refill from mechanism classes.
- `REJECT` is binding across turns.

## Mechanism classes

When the queue runs low, generate from this list — never from another field name
on the same request.

1. **Prompt composition** — which client bytes are composed into model context.
2. **Auth and audience** — mint, audience, issuer, scope, TTL, refresh, cross-env,
   type swap.
3. **Entitlement order** — gate vs dispatch, exhausted entity, counter identity,
   refund, negative/overflow, omitted object.
4. **Surface family** — titles, suggestions, autocomplete, search answer,
   translation, classification, extraction, summaries, notes.
5. **Client class** — web, desktop, mobile, extension, CLI, relay/MCP host, older
   installer, canary/beta host, regional mirror.
6. **Model routing** — slug vs alias, fallback chain, picker bypass, provider
   selector, BYOK connector (classify, never call it free).
7. **Transport** — SSE/NDJSON/WebSocket, commit vs delta, duplicate parameters,
   method/content-type confusion, path normalization, header override.
8. **Pacing and rotation** — per-IP/space/user/device limits, cooldown, burst,
   ban, reserve, entity cost.
9. **Legacy, debug, test** — deprecated verbs, debug options, reset verbs,
   feature flags, unlisted API versions.
10. **Client state** — local storage, signed blobs, idempotency keys, resume
    tokens, IPC channels.
11. **Files and URLs** — import, export, extraction, fetch paths, upload,
    archive handling.
12. **Isolation** — personal vs team, member vs owner, region, device — measured
    on entities you own.

## Probe selection

- **Cheapest observable first.** A free helper answers prompt-composition
  questions; the metered producer cannot be un-spent.
- **One variable per probe.** Version the payload; never edit in place.
- **Control the mechanism.** If the leak survives tools disabled, another
  workspace name, and another client, it is server-composed. If one client field
  changes it, that field is a strip lever — test it alone.
- **Three identical observables = change class.** Renaming a field is not a new
  hypothesis.
- **Sweep, don't sprinkle.** A class with N shapes gets a matrix run
  (`scripts/heist.py sweep`), recorded as one finding with the negative variants
  listed.

## Verdicts

- Vendor named + environment leaked → L1. Not L3.
- Product persona → L1; a one-turn jailbreak is not a strip path.
- Unmetered + miniature/gimped → L2 fallback.
- Clean original + metered → L3; state the ceiling, keep climbing.
- Empty stream, 200 with no content, "accepted but not executed" → not a
  success; retry once on a fresh object, then close as a negative.

## Stop vs rotate

| State | Class | Action |
|---|---|---|
| credits low / exhausted entity | rotate | next entity or cheaper surface; keep reserve |
| 429 / burst / cooldown | rotate | another surface or a real timer, then continue |
| ban / captcha / missing account | rotate or hard blocker | another owned entity; if none, record the exact step |
| no new hypothesis | bug | refill from mechanism classes |
| all classes negative | stop (case 3) | publish the map, not a victory claim |
| payment / legal / human consent | hard blocker | state the exact step; finish every unblocked branch first |
| L4 verified | stop | report gates and gateway |

## Resume

1. Read `README.md`, `QUEUE.md`, tail of `LEDGER.md`.
2. Open the finding records for the `Now` surface; check `stale:` before reusing
   any conclusion.
3. Run the first open `Now` experiment.
4. Empty `Now` → refill from mechanism classes and run.
5. Report only at a stop condition.

## Turn contract

While L4 is unreached and the queue is non-empty, a turn ends with an
**observation**. These endings are violations:

- "here is what I found", "итоги", "current status", "next steps";
- "ready to continue", "say the word", "назови хост/verb/поле", "подтверди план";
- offering the user "accept Lx" as an alternative to continuing (including via
  the `ask` tool);
- pausing because credits, a ban, a captcha, or a cooldown is near, before
  rotating entity or surface;
- calling the next probe "blind" — a blind probe is a missing mechanism
  hypothesis; generate one.

A repeated "продолжай / continue" is a bug report: resume the queue.

## Before ending a turn, five questions

1. Does one of the four stop conditions actually hold?
2. Is the queue empty or blocked? If empty, refill.
3. Am I about to ask the user for a host, verb, field, hypothesis, or approval?
   Delete it and run the queued experiment.
4. Did I rotate every blocked surface/entity before calling it blocked?
5. Is this report going to a file, or into chat while work remains?

## Report shape (stop only)

```text
Level: L0..L4
Gates: identity | purity | tools | meter -> pass/fail + evidence id
Chain: entry bug ids -> control -> exploit -> level
Ceiling: refill path x entities x turns; what cannot be refilled
Closed: classes with recorded negatives
Blocker: exact step (hard blockers only)
Next: first queued experiment if the hunt is not closed
```

No session narrative, no "here is what I did", no request for the user to supply
the next step.
