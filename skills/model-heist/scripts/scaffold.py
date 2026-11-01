#!/usr/bin/env python3
"""Create the campaign tree for one target.

    python scaffold.py acme-app --product "Acme" --channel text --out ../reverse

Writes reverse/<target>/ with the layout the skill mandates:
    README.md                  protocol map + level + findings index
    docs/QUEUE.md              mission contract (the binding one)
    docs/LEDGER.md             append-only probe table
    docs/BUGS.md               confirmed weaknesses
    docs/INVENTORY.md          artifacts, hashes, entities
    docs/findings/             raw dated probe records
    docs/TEMPLATES/            finding / bug / queue row shapes
    probes/ tools/ artifacts/  experiments / helpers / immutable captures
    state/                     tokens, cookies, profiles — gitignored

Refuses to overwrite an existing tree. Idempotent only in the sense that a
second run with the same name is an error you must resolve by reading it.
"""
from __future__ import annotations

import argparse
import os
import sys

QUEUE = """# QUEUE — mission contract

TARGET:        {product} (`{slug}`)
CHANNEL:       {channel}
ACCEPT:        provider-original (identity AND no product/tenant/tool leak) AND unmetered
REJECT:        product persona, jailbreak-only, BYOK, payment, account farm, third-party tenants
ENTITY BUDGET: {entities}
WORKING NOW:   (surface -> level -> evidence id)

## Now
1.

## Next
1.
2.
3.

## Closed (negatives — keep them)
- (none yet)

## Refill log
- (fill from mechanism classes when Now empties)
"""

LEDGER = """# LEDGER — one row per probe, negatives included

| id | ts | surface | payload sha | entities | result | level | evidence |
|---|---|---|---|---|---|---|---|
"""

BUGS = """# BUGS — confirmed weaknesses only

| id | class | source -> sink -> boundary | severity | level unlocked | evidence |
|---|---|---|---|---|---|
"""

INVENTORY = """# INVENTORY

## Artifacts
| path | version | sha256 | notes |
|---|---|---|---|

## Client classes present
- [ ] desktop shell (Electron / native / managed)
- [ ] web bundle
- [ ] mobile app
- [ ] browser extension
- [ ] CLI
- [ ] local daemon / sidecar / MCP host

## AI surfaces named by the product
| feature | transport | verb | observed status | originality |
|---|---|---|---|---|

## Your entities (never third-party)
| id | class | state | reserve? |
|---|---|---|---|
"""

README = """# {slug}

Target: {product}
Status: **L0** — no path found yet.

## Protocol map
(fill from `scripts/bundle_scan.py` + `docs/INVENTORY.md`; one row per surface)

| surface | verb | transport | auth | originality | level |
|---|---|---|---|---|---|

## Findings
See [docs/INDEX.md](docs/INDEX.md).

## Closed
(none yet)
"""

T_FINDING = """---
id: F-000
date: YYYY-MM-DD
surface: <host/path or feature>
build: <artifact sha or version>
verdict: <observation only>
---

# F-000 — <one line>

## Request
```
<method> <url>
<headers, secrets replaced by sha>
<body>
```

## Response
status: 000
```
<excerpt, or sha of the full body + where it is stored>
```

## Observation
-

## Inference
-

## Unknown
-

## Next
-
"""

T_BUG = """---
id: B-000
class: <authorization | entitlement | token | race | surface | meter>
severity: <none/low/medium/high>
level: <L0-L4 unlocked>
---

# B-000 — <one line>

source:      <byte you control>
sink:        <where the server acts on it>
boundary:    <the check that should exist>
least test:  <the request that differs only at the boundary>
evidence:    F-0xx
supersedes:  <none | B-0xx>
"""

T_QUEUE = """---
id: Q-000
state: now | next | closed
surface: <host/path>
hypothesis: <mechanism, not field name>
falsifier: <what result kills it>
cost: <entities / credits>
---

# Q-000 — <one line>
"""

GITIGNORE = """state/
artifacts/*.jsonl
artifacts/*.bin
*.pyc
__pycache__/
.venv/
"""


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("slug")
    ap.add_argument("--product", default=None)
    ap.add_argument("--channel", default="text")
    ap.add_argument("--entities", default="0 x 0 credits; reserve 0")
    ap.add_argument("--out", default="reverse")
    a = ap.parse_args()

    root = os.path.join(os.path.abspath(a.out), a.slug)
    if os.path.exists(root):
        print(f"refusing: {root} already exists — read it first", file=sys.stderr)
        return 2

    product = a.product or a.slug
    write(os.path.join(root, "README.md"), README.format(slug=a.slug, product=product))
    write(os.path.join(root, "docs", "QUEUE.md"),
          QUEUE.format(product=product, slug=a.slug, channel=a.channel, entities=a.entities))
    write(os.path.join(root, "docs", "LEDGER.md"), LEDGER)
    write(os.path.join(root, "docs", "BUGS.md"), BUGS)
    write(os.path.join(root, "docs", "INVENTORY.md"), INVENTORY)
    write(os.path.join(root, "docs", "TEMPLATES", "finding.md"), T_FINDING)
    write(os.path.join(root, "docs", "TEMPLATES", "bug.md"), T_BUG)
    write(os.path.join(root, "docs", "TEMPLATES", "queue-row.md"), T_QUEUE)
    write(os.path.join(root, ".gitignore"), GITIGNORE)
    for d in ("docs/findings", "probes", "tools", "artifacts", "state"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
        if d in {"artifacts", "state"}:
            write(os.path.join(root, d, ".gitkeep"), "")

    print(f"created {root}")
    print("next:")
    print(f"  python <skill>/scripts/gen_index.py {os.path.join(a.out, a.slug)}")
    print(f"  python <skill>/scripts/bundle_scan.py <extracted-tree> --out {os.path.join(a.out, a.slug, 'artifacts', 'sinks.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())