#!/usr/bin/env python3
"""Search the skill's own knowledge before reaching for a tool.

    python capability.py websocket
    python capability.py "meter bypass" --limit 12
    python capability.py apk --json

Why: this skill is a few thousand lines across references, a project profile map and
a 229-tool analysis server. Reading it linearly costs context; asking it a question
costs a second. Search-first is how the current agent-RE projects (jshookmcp and
friends) keep a large tool surface usable.

Index sources, in priority order:
    1. ~/.agents/skills/model-heist/SKILL.md and references/*.md
    2. <project>/study/PROFILES.md when a project dir is detected
    3. the REA CLI command list, when `rea` is installed

Output: ranked `file:line  text` hits with the section heading above each line.
Exit 1 when nothing matches, so a caller can branch.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADING = re.compile(r"^(#{1,4})\s+(.*)$")


def skill_docs() -> list[str]:
    docs = []
    main = os.path.join(SKILL_DIR, "SKILL.md")
    if os.path.exists(main):
        docs.append(main)
    ref = os.path.join(SKILL_DIR, "references")
    if os.path.isdir(ref):
        docs += [os.path.join(ref, f) for f in sorted(os.listdir(ref)) if f.endswith(".md")]
    return docs


def project_docs() -> list[str]:
    """study/PROFILES.md next to the working tree, if the caller is in a project."""
    out = []
    for root in (os.getcwd(), os.path.dirname(os.getcwd())):
        for rel in ("study/PROFILES.md", "docs/PROFILES.md", "PROFILES.md"):
            cand = os.path.join(root, *rel.split("/"))
            if os.path.exists(cand):
                out.append(cand)
                return out
    return out


def rea_commands() -> list[tuple[str, str]]:
    exe = shutil.which("rea")
    if not exe:
        npm = os.path.expandvars(r"%APPDATA%\npm\node_modules\rea-agents\scripts\rea.mjs")
        node = shutil.which("node")
        if not (node and os.path.exists(npm)):
            return []
        cmd = [node, npm, "--help"]
    else:
        cmd = [exe, "--help"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001
        return []
    rows = []
    for line in r.stdout.splitlines():
        m = re.match(r"^  ([a-z0-9][a-z0-9\-]{2,40})\s{2,}(.+)$", line)
        if m:
            rows.append((m.group(1), m.group(2).strip()))
    return rows


def index_lines(path: str):
    heading = ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            m = HEADING.match(line)
            if m:
                heading = m.group(2).strip()
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield n, heading, stripped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="+")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--context", action="store_true", help="show the section heading for each hit")
    a = ap.parse_args()

    terms = [t.lower() for t in " ".join(a.query).split() if t.strip()]
    if not terms:
        print("empty query", file=sys.stderr)
        return 2

    docs = skill_docs() + project_docs()
    hits = []
    for path in docs:
        if path.startswith(SKILL_DIR):
            rel = os.path.relpath(path, SKILL_DIR).replace("\\", "/")
        else:
            rel = f"{os.path.basename(os.path.dirname(path))}/{os.path.basename(path)}"
        for lineno, heading, text in index_lines(path):
            low = text.lower()
            score = sum(3 if t in low else 0 for t in terms)
            if heading and any(t in heading.lower() for t in terms):
                score += 4
            if score:
                hits.append({"file": rel, "line": lineno, "heading": heading,
                             "text": text[:220], "score": score})
    hits.sort(key=lambda h: (-h["score"], h["file"], h["line"]))
    hits = hits[: a.limit]

    cmds = [(name, desc) for name, desc in rea_commands()
            if any(t in (name + " " + desc).lower() for t in terms)][:8]

    if a.json:
        print(json.dumps({"query": " ".join(a.query), "docs": hits,
                          "rea_commands": [{"name": n, "desc": d} for n, d in cmds]},
                         indent=1))
        return 0 if (hits or cmds) else 1

    print(f"query: {' '.join(a.query)}\n")
    if hits:
        for h in hits:
            head = f"  [{h['heading'][:48]}]" if (a.context and h["heading"]) else ""
            print(f"{h['file']}:{h['line']}{head}")
            print(f"    {h['text']}")
    if cmds:
        print("\nREA commands:")
        for n, d in cmds:
            print(f"  rea {n:<34} {d[:70]}")
    if not hits and not cmds:
        print("no match. Broaden the query, or read SKILL.md directly.")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        import os as _os
        _os._exit(0)