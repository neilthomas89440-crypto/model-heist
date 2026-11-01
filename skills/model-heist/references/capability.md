# Capability: what to trust the model for

This skill is run by an LLM with tools. Its success rate is bounded by three things:
what it can read, what it can verify, and how long it can hold a large artifact in
context. Design the loop around those bounds instead of hoping.

## The honest split

| Work | Confidence | Rule |
|---|---|---|
| Read pseudocode / minified JS and say what it does | high | cite file:line or function address |
| Diff two versions of a bundle and name the changed behaviour | high | show the diff hunk |
| Write a converter (Anthropic ⇄ OpenAI ⇄ Gemini), a gateway, a replay script | high | run it against a stub before claiming it works |
| Name the mechanism behind an observed request field | medium | label `inference` until a replay reproduces it |
| Recall an exact offset, opcode, header name, or ABI signature | **low** | never: derive from the artifact every time |
| Predict whether a payload bypasses a gate | **low** | test it; a prediction is a queue entry, not a finding |
| Judge "the app works" from a screenshot | **low** | log the request and read the response |
| Keep a 16 MB bundle "in mind" | **none** | summary-first, then page specific views |

The two hard limits: **the model cannot inspect its own computation**, and **it has no
memory between sessions except what is on disk**. Anything not written as a finding
record is gone.

## Where it hallucinates — and the tell

| Symptom | What actually happened | Countermeasure |
|---|---|---|
| Confident function name in decompiled output | Ghidra's default `FUN_00...` was renamed by the model | quote the address and the raw name, not the guess |
| "This header likely bypasses the gate" | pattern matching on the word "admin" | run the control request; record both responses |
| Endpoint that 404s | invented from a similar product | only use hosts/paths seen in a capture or a bundle |
| Base64 blob described as "probably the key" | length/entropy guess | decrypt with it and show plaintext, or label unknown |
| Offsets that differ from the real binary | recalled instead of measured | `open_binary`/`inspect_binary_layout`, quote the tool's address |
| "Fixed" after one green run | the run exercised a different path | reproduce the original failing scenario, then the fixed one |

## Verification protocol

Every load-bearing claim carries exactly one of:

1. a captured response (file, line, sha256 of the body),
2. a file:line from an extracted artifact (with the artifact's sha256),
3. a decompiler/analysis record keyed to an address or evidence id,
4. a runtime observation (frida log line, console output, counter delta).

If none is available: the claim is labelled `unverified` and it is a queue item.
No exceptions for "obvious" facts.

Control requests: for any claim of form "removing X changed the behaviour", you must
have the request with X and the request without X, differing in nothing else.

## Context discipline

Large artifacts degrade reasoning before they exhaust the window: accuracy on the
first 20% of a long file is much higher than on the whole of it. Therefore:

- `bundle_scan.py` first (`sinks.json`), read the ranked sink list, then open only the
  files it points at.
- REA summary mode → inspect specific views by evidence id; never re-run analysis to
  "see it again".
- Keep the working set to: current hypothesis, its evidence ids, the three queued
  experiments. Everything else lives in `docs/`.
- When a document grows past its usefulness, add a curated `docs/<topic>.md` that
  cites finding ids instead of rereading raw records.

## What to delegate to code

Anything deterministic belongs in a script, because a script cannot be
plausible-but-wrong:

| Task | Script |
|---|---|
| source→sink mapping | `bundle_scan.py` |
| identity/purity/tools/meter gates | `heist.py` |
| capture | `proxy.py`, `cdp_capture.py` |
| doc index | `gen_index.py` |
| scaffolding | `scaffold.py` |
| decoding envelopes, reimplementing a signature | write once in `probes/`, keep it |
| pacing curves, retry/backoff measurement | small loop with the ledger writing each attempt |

The model chooses *what to test next*; the code decides *what happened*.

## Self-check before claiming a gate

1. Did I actually send the request, or do I remember sending it?
2. Is the raw response archived, or only a summary?
3. Is there a control request differing in exactly one variable?
4. Would this claim survive if the target's marketing copy were deleted?
5. Have I tested this same shape three times with the same observable? (Then stop
   varying fields and change mechanism class.)
6. Is the level I am claiming backed by all gates, or by the two I liked?

A "no" anywhere means the level is unchanged and the queue is not empty.