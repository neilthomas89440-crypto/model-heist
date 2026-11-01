# model-heist

A reverse-engineering workflow for coding agents whose goal is not "understand the app"
but **a working, unmetered route to the provider's original models** — the same models a
vendor's gateway serves, reached through the vendor's own product rather than through a
paid key.

Two skills, one loop:

| skill | job |
|---|---|
| [`skills/model-heist`](skills/model-heist) | recon → traffic capture → credential/meter map → trust-boundary hunt → gateway, with an evidence trail and a coverage gate |
| [`skills/autoreg-pools`](skills/autoreg-pools) | the separate breadth track: accounts → pool → one OpenAI-compatible endpoint |

It is not a jailbreak pack and not a wrapper. The deliverable is a route that passes four
gates — **identity, purity, tools, meter** — and, when a model catalog is in scope, covers
that catalog or carries a per-id proof of why not.

## Why this exists

An agent with a disassembler and no discipline produces confident fiction. This workflow
is built around the three things that keep it honest:

1. **Evidence typing.** Every load-bearing claim carries an artifact hash, a file offset,
   a decompiler address, or a captured response. A tool summary is not evidence for a
   payload.
2. **A gate you did not run is not passed.** Identity, purity, tool passthrough and meter
   each need a captured request/response pair. "It answered" is not a result.
3. **Coverage, or a proof per id.** One working model is a baseline, not a win. The stop
   condition is the whole catalog — or a reproducible row per excluded id: request,
   response, a control request that differs only in the model id, and the layer the error
   came from (transport / authn / authz / catalog / routing / capacity).

## Install

The skills follow the Agent Skills layout: a directory per skill with `SKILL.md` at its
root. Drop them where your agent looks for skills.

```powershell
# Windows
.\install.ps1            # copies both skills into %USERPROFILE%\.agents\skills
```

```bash
# macOS / Linux
./install.sh             # copies both skills into ~/.agents/skills
```

Any agent that reads `SKILL.md` files works: oh-my-pi / omp, Claude Code, Codex, Cursor,
Gemini CLI. The scripts are plain Python 3.10+ with no install step of their own.

## Quick start

```bash
S=~/.agents/skills/model-heist/scripts

python $S/doctor.py                     # what this machine can actually do
python $S/intake.py <target>            # class + route + the exact next commands
python $S/triage.py <binary>            # first-minute static pass
python $S/scaffold.py <name> --out reverse
```

Then follow `skills/model-heist/SKILL.md`. It is a phase-ordered workflow, not a tool
catalogue: frame → map → capture → credentials → meter → hunt → gateway, with a queue and
a ledger that survive the session.

## What's inside

```
skills/model-heist/
  SKILL.md                    the workflow (phases, gates, stop conditions)
  references/
    traffic.md                interception ladder: CDP, MITM, pinning, QUIC, mobile
    routing.md                artifact class → tool → extraction, native first
    exploit-classes.md        A–P catalogue and the chains that reach L4
    auth-entitlement.md       mint, replay, gate order, meter model
    prompt-and-meter.md       prompt sinks, canaries, model-id trust, meter bypass
    surface-map.md            what to enumerate before touching anything
    web-attack.md             HTTP-level payload shapes per class
    gateway.md                the OpenAI-compatible productisation contract
    evidence-and-queue.md     ledger, findings, resume, stop vs rotate
    capability.md             what to trust the model for, and what to code instead
    workflow-map.md           how public agentic-RE stacks are built, and what we took
    corpus.md                 mechanisms verified in real reverse-engineering projects
  scripts/
    doctor.py                 machine capability table + exact fixes
    intake.py                 classify a target and print its route
    triage.py                 hashes, entropy, strings, imports, capa, floss, YARA
    bundle_scan.py            source→sink map over an extracted bundle
    web_bundle.py             static pass for a URL: scripts, maps, hosts, endpoints
    proxy.py                  self-contained MITM proxy with a dynamic CA (WS/WSS too)
    capture.py                the same capture as a mitmproxy addon
    cdp_capture.py            CDP network capture for browser/Electron targets
    cdp_debug.py              breakpoints, scope variables, pre-send request hook
    heist.py                  the four gates, plus send/sweep, over a JSONL ledger
    models.py                 live model catalog: fetch, diff against a bundle, coverage
    capability.py             search this skill before reaching for a tool
    scaffold.py               campaign tree for one target
    gen_index.py              regenerate docs/INDEX.md

skills/autoreg-pools/
  SKILL.md                    account pipeline, hygiene, rotation, economics
  scripts/pool_gateway.py     accounts.jsonl → one OpenAI-compatible endpoint
```

## Two ideas worth stealing even if you never run this

- **Triage before decompiling.** `triage.py --dir <app>` for desktop apps: triage the
  app's own native modules and its JS bundle, not the 240 MB Chromium shell. capa on a
  shell binary costs minutes and returns generic results.
- **A partial hit is a baseline.** A surface that answers for 3 of 58 model ids is a
  *route*, not a deliverable: record it, keep it live, and keep enumerating. Coverage is
  the union over routes, and a route that answers one id may be the only one that still
  works after the others rotate.

## Scope

The workflow is written for targets **you run**: your machine, your installs, your
accounts. `SKILL.md` draws that line explicitly and stops at another tenant's data, not
because it is hard but because it is not the deliverable and it pollutes the evidence.
Everything the workflow produces is reproducible: a finding without a capture, a hash or
an address is labelled `unverified` and stays a queue item.

## License

MIT — see [LICENSE](LICENSE).