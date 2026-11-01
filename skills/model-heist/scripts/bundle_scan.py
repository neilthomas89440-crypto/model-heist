#!/usr/bin/env python3
"""Static source-to-sink scan over an extracted application tree.

Purpose: turn "a shipped bundle" into a ranked list of places where the server
or client acts on attacker-controlled bytes. Output is a machine-readable map,
not a verdict: every record is a *candidate* until a probe confirms it.

Usage:
    python bundle_scan.py <tree> [--out sinks.json] [--max-bytes 2000000]
                          [--ext .js,.ts,.py,.go,.java,.kt,.cs,.swift,.mjs,.cjs]
                          [--class model_dispatch,token_mint] [--top 12]

Design constraints (deliberate):
  * bounded: byte cap per file, file cap, entries cap per class
  * deterministic: sorted output, no timestamps in the payload
  * no execution: pure text scan, never imports or runs target code
  * offline: no network, no telemetry
"""
from __future__ import annotations

import argparse
import hashlib
import json
import bisect
import os
import re
import sys
from collections import Counter, defaultdict

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "target",
    "__pycache__", ".venv", "venv", "site-packages", ".next", ".nuxt",
    "vendor", "Pods", "DerivedData", "obj", "bin", ".idea", ".vs",
}
SKIP_SUFFIX = (".map", ".min.js.map", ".lock", ".png", ".jpg", ".jpeg",
               ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".mp4",
               ".zip", ".gz", ".7z", ".jar", ".dll", ".exe", ".so", ".dylib")

# class -> (regex, why it matters). Ordered by hunt value, not by name.
SINKS: list[tuple[str, str, str]] = [
    ("auth_gate",
     r"\b(?:authorize|isAuthorized|is_authorized|hasPermission|has_permission|"
     r"canAccess|can_access|checkPermission|check_permission|requireAuth|"
     r"isAuthenticated|verifyToken|assert_owner|requireLogin|ensureAuth)\b",
     "the check that is supposed to stop you; read its inputs and its order"),
    ("entitlement",
     r"\b(?:entitlement|subscription_?(?:status|tier|plan)|plan_?id|planId|"
     r"credits?_?(?:remaining|left|balance)|quota_?(?:remaining|left)|"
     r"is_?pro|has_?pro|upgrade_?required|payment_?required|trial_?end)\b",
     "plan/credit gate: what it reads decides whether an id, a flag or a header buys you the model"),
    ("model_dispatch",
     r"(?:chat/completions|/v1/(?:models|messages|responses)|generateContent|"
     r"model_?id|modelId|owned_by|max_?tokens|temperature|"
     r"\b(?:openai|anthropic|gemini|ollama|litellm|openrouter|bedrock|vertex)\b)",
     "where a model actually runs; the id you can influence is the id you get"),
    ("token_mint",
     r"(?:\bsign\(|jwt\.(?:sign|verify)|createToken|mint_?token|"
     r"access_?token|refresh_?token|id_?token|api_?key|apikey|bearer\b|"
     r"x-api-key|client_?secret)",
     "credential creation and transport; replay these upstream with no product headers"),
    ("url_fetch",
     r"(?:\bfetch\(|\baxios\.|\brequests\.(?:get|post|put)|\burllib\b|\bhttpx\.|"
     r"\bhttp\.(?:Get|Post|NewRequest)|\bHttpClient\b|\bWebClient\b|\bOkHttp\b|"
     r"\bcurl\s+https?://|openai\.(?:chat|responses|audio)|Anthropic\()",
     "outbound calls: hosts, paths, and which of them carry your bytes"),
    ("prompt_assembly",
     r"(?:system_?prompt|systemPrompt|\"system\"\s*:|'system'\s*:|"
     r"\brole\s*:\s*[\"']system[\"']|\binstructions\b|prepend|"
     r"\bprompt_?template|buildPrompt|composePrompt)",
     "prompt sinks: whatever is composed here is what makes a route a wrapper"),
    ("credit_write",
     r"(?:decrement|deduct|charge_?user|consume_?credit|spend_?credit|"
     r"balance\s*-=|credits?\s*-=|usage\s*\+?=|record_?usage|increment_?usage)",
     "the meter write; if a call path skips this line, that call is free"),
    ("rate_limit",
     r"(?:rate_?limit|rateLimit|429|throttle|retry_?after|burst|"
     r"too_?many_?requests|cooldown)",
     "pacing shape: what the server thinks one entity is worth per interval"),
    ("feature_flag",
     r"(?:feature_?flag|growthbook|launchdarkly|unleash|split\.io|"
     r"\bisEnabled\(|\bcanary\b|experiment_?id|remote_?config)",
     "flags gate alternate code paths and alternate model routes"),
    ("admin_debug",
     r"(?:/debug\b|/admin\b|/internal\b|__dev\b|localhost:\d{2,5}|"
     r"127\.0\.0\.1:\d{2,5}|test_?mode|bypass|dev_?only|skip_?auth)",
     "debug/legacy surfaces routinely skip the gate the product ships"),
    ("crypto_hook",
     r"(?:crypto\.subtle|CryptoJS|AES|encrypt|decrypt|\bhmac\b|SM2|SM3|SM4|"
     r"signature|nonce|x-sign|publicKeyPem|privateKey)",
     "client-side signing: the algorithm you must reimplement to talk to the API yourself"),
]
SINK_RE = [(c, re.compile(p, re.M | re.I), w) for c, p, w in SINKS]

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
PATH_RE = re.compile(r"[\"'`](/?(?:api|v\d|rpc|graphql|ws|socket|auth)/"
                     r"[A-Za-z0-9._~/{}$:-]{1,120})[\"'`]")
MODEL_RE = re.compile(
    r"[a-z0-9][a-z0-9._-]{1,40}(?::(?:free|mini|fast|mini-free))?"
)
FAMILY_RE = re.compile(r"(gpt|claude|gemini|deepseek|qwen|glm|kimi|grok|"
                       r"llama|mistral|nova|nemotron|minimax|mimo|sonnet|opus|haiku)",
                       re.I)

MAX_HITS_PER_CLASS = 4000

# Model ids are the first thing you want from a bundle and the noisiest regex target:
# bare hostnames and URL fragments match any naive pattern. Accept only ids that look
# like a provider-model-version, reject anything that is obviously a host or a path.
# A family name must be followed by a separator + version: "claude-opus-5" is a model,
# "commands" and "philippines" are not. Short families (o1/o3) need an explicit boundary.
MODEL_FAMILIES = re.compile(
    r"^(?:(?:claude|gpt|gemini|grok|deepseek|qwen|glm|kimi|llama|mistral|nova|minimax|"
    r"mimo|sonar|beam|nemotron|command-r|ernie|hunyuan|doubao)[-.][a-z0-9]"
    r"|o[1-9](?:[-.]|$))", re.I)
HOST_SUFFIX = re.compile(r"\.(?:com|net|org|io|so|ai|co|dev|app|cloud|cn|ru|de|uk)$", re.I)
BARE_HOST = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|so|ai|co|dev|app|cloud|cn|ru|de|uk))\b", re.I)
HOST_NOISE = re.compile(r"(?:^|\.)(?:w3\.org|xml|svg|sentry|amplitude|github|npmjs|mozilla|"
                        r"example|schema|xmlns)", re.I)


UI_CLASS = re.compile(
    r"^(?:gap|gap-x|gap-y|px|py|pt|pb|pl|pr|p|mx|my|mt|mb|ml|mr|m|w|h|min|max|size|flex|"
    r"shrink|grow|basis|order|text|bg|border|rounded|opacity|z|top|left|right|bottom|inset|"
    r"space|leading|tracking|grid|col|row|translate|scale|rotate|duration|delay|ease|animate|"
    r"font|aspect|divide|ring|outline|blur|backdrop|accent|caret|columns|content|cursor|fill|"
    r"stroke|from|to|via|indent|justify|items|self|place|overflow|object|isolate|mix|sr|"
    r"first|last|odd|even|hover|focus|active|disabled|group|peer|dark|sm|md|lg|xl|print)-[\w.]+$",
    re.I)


def is_model_id(token: str) -> bool:
    t = token.strip().strip('"\'`')
    if not t or len(t) < 4 or len(t) > 60:
        return False
    if "://" in t or "/" in t or "@" in t:
        return False
    if HOST_SUFFIX.search(t):
        return False
    if not re.search(r"[a-z]", t, re.I):
        return False
    if MODEL_FAMILIES.match(t):
        return True
    if UI_CLASS.match(t):
        return False
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:[-.][a-z0-9]+){1,5}", t):
        return False
    if not re.search(r"\d", t) or len(t) < 6:
        return False
    # a dot is only credible between digits (gemini-3.5-flash), not as a member access
    if "." in t and not re.search(r"\d\.\d", t):
        return False
    return True


def iter_files(root: str, exts: set[str]):
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not d.startswith(".git"))
        for name in sorted(filenames):
            low = name.lower()
            if low.endswith(SKIP_SUFFIX):
                continue
            if exts and os.path.splitext(low)[1] not in exts:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            seen += 1
            yield path


def scan(root: str, exts: set[str], wanted: set[str]):
    sinks: dict[str, list[dict]] = defaultdict(list)
    urls: Counter = Counter()
    bare_hosts: Counter = Counter()
    paths: Counter = Counter()
    models: Counter = Counter()
    family_models: Counter = Counter()
    per_file: dict[str, str] = {}
    files = 0
    lines_total = 0

    for path in iter_files(root, exts):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_FILE_BYTES)
        except OSError:
            continue
        files += 1
        rel = os.path.relpath(path, root).replace("\\", "/")
        per_file[rel] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        lines = text.split("\n")
        lines_total += len(lines)
        # line lookup for hits: build the newline index once, bisect per hit.
        # A per-hit text.count() is O(file) and dominates runtime on large bundles.
        nl = [m.start() for m in re.finditer("\n", text)]

        for cls, rx, _why in SINK_RE:
            if wanted and cls not in wanted:
                continue
            if len(sinks[cls]) >= MAX_HITS_PER_CLASS:
                continue
            for m in rx.finditer(text):
                line_no = bisect.bisect_right(nl, m.start()) + 1
                snippet = lines[line_no - 1].strip()[:240] if line_no <= len(lines) else ""
                sinks[cls].append({
                    "class": cls, "file": rel, "line": line_no, "text": snippet,
                })
                if len(sinks[cls]) >= MAX_HITS_PER_CLASS:
                    break

        for m in URL_RE.finditer(text):
            urls[m.group(0)[:160]] += 1
        for m in PATH_RE.finditer(text):
            paths[m.group(1)] += 1
        for m in MODEL_RE.finditer(text):
            tok = m.group(0)
            if is_model_id(tok):
                models[tok] += 1
                if MODEL_FAMILIES.match(tok):
                    family_models[tok] += 1
        for m in BARE_HOST.finditer(text):
            host = m.group(1).lower()
            if not HOST_NOISE.search(host):
                bare_hosts[host] += 1

    return sinks, urls, paths, models, family_models, bare_hosts, per_file, files, lines_total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tree")
    ap.add_argument("--out", default="sinks.json")
    ap.add_argument("--max-bytes", type=int, default=2_000_000)
    ap.add_argument("--ext", default=".js,.mjs,.cjs,.ts,.tsx,.jsx,.py,.go,.java,"
                                    ".kt,.cs,.swift,.rb,.php,.rs,.lua,.dart")
    ap.add_argument("--class", dest="classes", default="")
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    global MAX_FILE_BYTES
    MAX_FILE_BYTES = args.max_bytes
    root = os.path.abspath(args.tree)
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    exts = {e.strip().lower() for e in args.ext.split(",") if e.strip()}
    wanted = {c.strip() for c in args.classes.split(",") if c.strip()}

    sinks, urls, paths, models, family_models, bare_hosts, per_file, files, lines = scan(root, exts, wanted)

    payload = {
        "root": root,
        "files_scanned": files,
        "lines_scanned": lines,
        "file_digests": dict(sorted(per_file.items())[:5000]),
        "sinks": {k: v[:MAX_HITS_PER_CLASS] for k, v in sorted(sinks.items())},
        "counts": {k: len(v) for k, v in sorted(sinks.items())},
        "urls": urls.most_common(500),
        "endpoint_paths": paths.most_common(500),
        "model_ids": models.most_common(300),
        "model_ids_family": family_models.most_common(200),
        "bare_hosts": bare_hosts.most_common(200),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=False)
        fh.write("\n")

    print(f"scanned {files} files / {lines} lines under {root}")
    print(f"wrote {os.path.abspath(args.out)}\n")
    print(f"{'class':<16}{'hits':>7}  top files")
    for cls, rows in sorted(sinks.items(), key=lambda kv: -len(kv[1])):
        by_file = Counter(r["file"] for r in rows).most_common(3)
        top = ", ".join(f"{f}({n})" for f, n in by_file)
        print(f"{cls:<16}{len(rows):>7}  {top}")
    fam = [m for m, _ in family_models.most_common(20)]
    other = [m for m, _ in models.most_common(60) if m not in set(fam)][:10]
    print("\nmodel ids (family match):", ", ".join(fam) or "-")
    print("model-ish (unverified):   ", ", ".join(other) or "-")
    print("hosts:", ", ".join(u for u, _ in urls.most_common(6)))
    if bare_hosts:
        api_like = [h for h, _ in bare_hosts.most_common(200)
                    if any(k in h for k in ("api", "gateway", "ws", "rpc", "llm"))
                    or h.count(".") >= 3]
        print("api hosts:  ", ", ".join(api_like[:10]) or "-")
        print("bare hosts: ", ", ".join(h for h, _ in bare_hosts.most_common(6)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError) as _exc:
        # a closed pipe (`| head`) is not an error; do not traceback into the caller
        import os as _os, sys as _sys
        try:
            _sys.stdout.flush()
        except Exception:  # noqa: BLE001
            pass
        _os._exit(0)
