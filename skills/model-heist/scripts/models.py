#!/usr/bin/env python3
"""Read a live model catalog and reconcile it with what the target advertises.

A bundle's model strings are yesterday's guess; the gateway's `/v1/models` is
today's truth. This tool fetches the catalog, normalises it, and diffs it against
the ids found by `bundle_scan.py`, so a heist starts from the real list.

    python models.py catalog --base https://llm-gateway.example/v1 --key $K \\
        --out artifacts/catalog.json

    python models.py diff --catalog artifacts/catalog.json \\
        --sinks artifacts/sinks-app.json

    python models.py grep --catalog artifacts/catalog.json claude

    python models.py probe --catalog artifacts/catalog.json \\
        --base https://llm-gateway.example/v1 --key $K --model claude-opus-5 \\
        --product acme --ledger artifacts/ledger.jsonl

Catalog shapes handled: OpenAI `{data:[...]}`, `{models:[...]}`, a bare list, and
LiteLLM/OpenRouter-style entries with `pricing` per million tokens.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

try:
    import httpx
except ImportError:
    print("need httpx: pip install httpx", file=sys.stderr)
    raise SystemExit(2)

PRICE_KEYS = ("prompt", "completion", "completions", "input", "output")


def fetch_catalog(base: str, key: str | None, timeout: float = 40.0) -> list[dict]:
    url = base.rstrip("/") + "/models"
    headers = {"accept": "application/json", "user-agent": "model-heist/1"}
    if key:
        headers["authorization"] = f"Bearer {key}"
    with httpx.Client(timeout=timeout, follow_redirects=True) as c:
        r = c.get(url, headers=headers)
    r.raise_for_status()
    payload = r.json()
    if isinstance(payload, list):
        raw = payload
    else:
        raw = payload.get("data") or payload.get("models") or []
    return [normalise(m) for m in raw if isinstance(m, dict) or isinstance(m, str)]


def normalise(item) -> dict:
    if isinstance(item, str):
        return {"id": item}
    out = {"id": item.get("id") or item.get("name") or ""}
    name = item.get("name")
    if name and name != out["id"]:
        out["name"] = name
    ctx = item.get("context_length") or (item.get("top_provider") or {}).get("context_length")
    if ctx:
        out["ctx"] = ctx
    top = item.get("top_provider") or {}
    if top.get("is_moderated") is not None:
        out["moderated"] = bool(top["is_moderated"])
    if top.get("max_completion_tokens"):
        out["max_out"] = top["max_completion_tokens"]
    pricing = item.get("pricing")
    if isinstance(pricing, dict):
        flat = {}
        for scope, val in pricing.items():
            if not isinstance(val, dict):
                continue
            for k, v in val.items():
                if k in PRICE_KEYS and isinstance(v, (int, float)):
                    flat[f"{scope}.{k}"] = v
        price = {k: v for k, v in flat.items() if "prompt" in k or "completion" in k or k.endswith(".input") or k.endswith(".output")}
        if price:
            out["price"] = price
    for k in ("creator", "owned_by", "provider"):
        if item.get(k):
            out["provider"] = item[k]
            break
    if item.get("supported_parameters"):
        out["params"] = item["supported_parameters"]
    return out


def shorten(price: dict | None) -> str:
    if not price:
        return "-"
    for scope in ("global", "per_million", "per_1m"):
        p = price.get(f"{scope}.prompt")
        c = price.get(f"{scope}.completions") or price.get(f"{scope}.completion")
        if p is not None:
            return f"{p}/{c if c is not None else '?'}"
    p = next((v for k, v in price.items() if "prompt" in k or k.endswith("input")), None)
    c = next((v for k, v in price.items() if "completion" in k or k.endswith("output")), None)
    return f"{p}/{c}" if p is not None else "-"


def cmd_catalog(a) -> int:
    models = fetch_catalog(a.base, a.key, a.timeout)
    models.sort(key=lambda m: m["id"])
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump({"base": a.base, "models": models}, fh, indent=1)
            fh.write("\n")
    if a.json:
        print(json.dumps({"base": a.base, "count": len(models), "models": models}, indent=1))
        return 0
    print(f"{len(models)} models from {a.base}/models\n")
    print(f"{'id':<40}{'ctx':>9}{'price in/out':>16}  mod  provider")
    for m in models:
        print(f"{m['id'][:39]:<40}{str(m.get('ctx','-')):>9}{shorten(m.get('price')):>16}"
              f"  {('no' if m.get('moderated') is False else ('yes' if m.get('moderated') else '-')):<4} "
              f"{m.get('provider','')}")
    if a.out:
        print(f"\nwrote {os.path.abspath(a.out)}")
    return 0


def load_catalog(path: str) -> list[dict]:
    d = json.load(open(path, encoding="utf-8"))
    return d.get("models") if isinstance(d, dict) else d


def bundle_ids(sinks_path: str) -> set[str]:
    """Prefer the family-filtered list; fall back to the loose one on old sinks files."""
    d = json.load(open(sinks_path, encoding="utf-8"))
    rows = d.get("model_ids_family") or d.get("model_ids") or []
    return {m for m, _ in rows}


def cmd_diff(a) -> int:
    catalog = {m["id"] for m in load_catalog(a.catalog)}
    bundle = bundle_ids(a.sinks)
    both = sorted(catalog & bundle)
    only_bundle = sorted(bundle - catalog)
    only_catalog = sorted(catalog - bundle)
    print(f"catalog: {len(catalog)}   bundle: {len(bundle)}\n")
    print(f"in both ({len(both)}): {', '.join(both[:20]) or '-'}")
    print(f"\nonly in bundle ({len(only_bundle)}) — aliases, old ids, or fiction:")
    for m in only_bundle[:30]:
        print("  ", m)
    if a.all_catalog:
        print(f"\nonly in catalog ({len(only_catalog)}): {', '.join(only_catalog[:40])}")
    else:
        print(f"\nonly in catalog: {len(only_catalog)} ids (use --all-catalog to list)")
    return 0


def cmd_grep(a) -> int:
    pat = re.compile(a.pattern, re.I)
    rows = [m for m in load_catalog(a.catalog) if pat.search(m["id"])]
    for m in rows:
        print(f"{m['id']:<42}{str(m.get('ctx','-')):>9}{shorten(m.get('price')):>16}  {m.get('provider','')}")
    return 0 if rows else 1


ERR_CLASS = [
    ((401, 403), "auth"),
    ((402,), "quota"),
    ((404,), "not_found"),
    ((429,), "rate"),
    ((400,), "bad_request"),
    ((500, 502, 503, 504), "upstream"),
]


def classify_status(status: int | None, body: str) -> str:
    if status == 200:
        return "ok"
    for codes, name in ERR_CLASS:
        if status in codes:
            return name
    low = (body or "").lower()
    if "model" in low and ("not found" in low or "unknown" in low or "does not exist" in low):
        return "no_model"
    return f"http_{status}" if status else "transport"


def _probe_one(url: str, key: str | None, mid: str, timeout: float) -> dict:
    import json as _json
    import time as _time
    headers = {"content-type": "application/json", "accept": "application/json"}
    if key:
        headers["authorization"] = f"Bearer {key}"
    body = {"model": mid, "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1, "stream": False}
    t0 = _time.time()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.post(url, json=body, headers=headers)
            status, text = r.status_code, r.text[:2000]
    except Exception as exc:  # noqa: BLE001
        return {"status": None, "class": "transport", "ms": int((_time.time() - t0) * 1000),
                "detail": f"{type(exc).__name__}: {exc}"[:200]}
    cls = classify_status(status, text)
    detail = ""
    if cls != "ok":
        try:
            err = _json.loads(text)
            detail = str(err.get("error", {}).get("message") or err.get("error") or text)[:180]
        except Exception:  # noqa: BLE001
            detail = text[:180]
    return {"status": status, "class": cls, "ms": int((_time.time() - t0) * 1000),
            "detail": detail}


def cmd_coverage(a) -> int:
    """Probe catalog ids across one or many routes; a partial hit is a baseline, not a stop.

    --routes routes.json              [{"name","base","key"}] — merged matrix
    --base/--key                      single route (equivalent to one entry)
    """
    import json as _json
    from concurrent.futures import ThreadPoolExecutor

    routes: list[dict] = []
    if a.routes:
        routes = _json.load(open(a.routes, encoding="utf-8"))
        if isinstance(routes, dict):
            routes = routes.get("routes") or []
    if a.base:
        routes.append({"name": a.name or "default", "base": a.base, "key": a.key})
    if not routes:
        print("no route: pass --base or --routes", file=sys.stderr)
        return 2

    ids = [m["id"] for m in load_catalog(a.catalog)]
    if a.only:
        wanted = {x.strip() for x in a.only.split(",") if x.strip()}
        ids = [i for i in ids if i in wanted]
    if a.limit:
        ids = ids[: a.limit]
    if not ids:
        print("empty catalog selection", file=sys.stderr)
        return 2

    matrix: dict[str, dict[str, dict]] = {mid: {} for mid in ids}
    for route in routes:
        name = route.get("name") or "route"
        url = route["base"].rstrip("/") + "/chat/completions"
        key = route.get("key") or a.key
        pending = [m for m in ids if a.retest or not any(
            r["class"] == "ok" for r in matrix[m].values())]
        if not pending:
            continue
        print(f"route {name}: {len(pending)} ids to probe")
        with ThreadPoolExecutor(max_workers=max(1, a.concurrency)) as pool:
            def work(mid):
                return mid, _probe_one(url, key, mid, a.timeout)
            for mid, rec in pool.map(work, pending):
                matrix[mid][name] = rec
                if a.ledger:
                    with open(a.ledger, "a", encoding="utf-8") as fh:
                        fh.write(_json.dumps({"op": "coverage", "route": name,
                                              "model": mid, **rec}) + "\n")
        if a.interval:
            import time as _t
            _t.sleep(a.interval)

    covered = [m for m in ids if any(r["class"] == "ok" for r in matrix[m].values())]
    print(f"\n{'model':<44}" + "".join(f"{r.get('name','route')[:12]:<14}" for r in routes))
    for mid in ids:
        cells = []
        for r in routes:
            rec = matrix[mid].get(r.get("name") or "route") or {}
            cells.append(f"{(rec.get('class') or '-')[:12]:<14}")
        print(f"{mid[:43]:<44}" + "".join(cells))
    print(f"\ncoverage: {len(covered)}/{len(ids)} ids answered by at least one route "
          f"({100*len(covered)/len(ids):.1f}%)")
    for r in routes:
        name = r.get("name") or "route"
        y = sum(1 for m in ids if matrix[m].get(name, {}).get("class") == "ok")
        print(f"  {name:<16}{y}/{len(ids)} ids")
    missing = [m for m in ids if m not in covered]
    if missing:
        print(f"\n{len(missing)} ids not covered by any route — record a proof row per id,")
        print("then change route/entitlement layer or target. Do not stop at coverage < 100%.")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as fh:
            _json.dump({"routes": [r.get("name") for r in routes], "total": len(ids),
                        "covered": len(covered), "matrix": matrix}, fh, indent=1)
        print(f"wrote {os.path.abspath(a.out)}")
    return 0 if len(covered) == len(ids) else 1


def _cmd_coverage_legacy(a) -> int:
    """Probe every catalog id through one route and report per-id reachability.

    This is the gate for "the whole catalog, not one model": per-id status, error
    class, latency, and a machine-readable ledger. A model that is unreachable is
    not "absent" — it is unreachable through THIS route, with the exact error that
    proves it.
    """
    import json as _json
    import time as _time
    from concurrent.futures import ThreadPoolExecutor

    ids = [m["id"] for m in load_catalog(a.catalog)]
    if a.only:
        wanted = {x.strip() for x in a.only.split(",") if x.strip()}
        ids = [i for i in ids if i in wanted]
    if a.limit:
        ids = ids[: a.limit]
    if not ids:
        print("empty catalog selection", file=sys.stderr)
        return 2

    url = a.base.rstrip("/") + "/chat/completions"
    headers = {"content-type": "application/json", "accept": "application/json"}
    if a.key:
        headers["authorization"] = f"Bearer {a.key}"

    def one(mid: str) -> dict:
        body = {"model": mid, "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1, "stream": False}
        t0 = _time.time()
        try:
            with httpx.Client(timeout=a.timeout, follow_redirects=False) as c:
                r = c.post(url, json=body, headers=headers)
                text = r.text[:2000]
                status = r.status_code
        except Exception as exc:  # noqa: BLE001
            return {"model": mid, "status": None, "class": "transport",
                    "ms": int((_time.time() - t0) * 1000),
                    "detail": f"{type(exc).__name__}: {exc}"[:200]}
        cls = classify_status(status, text)
        detail = ""
        if cls != "ok":
            try:
                err = _json.loads(text)
                detail = str(err.get("error", {}).get("message") or err.get("error") or text)[:180]
            except Exception:  # noqa: BLE001
                detail = text[:180]
        return {"model": mid, "status": status, "class": cls,
                "ms": int((_time.time() - t0) * 1000), "detail": detail}

    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, a.concurrency)) as pool:
        for rec in pool.map(one, ids):
            rows.append(rec)
            mark = "ok " if rec["class"] == "ok" else rec["class"][:9]
            print(f"  {rec['model'][:44]:<46}{mark:<10}{str(rec['status']):<5}{rec['ms']:>6} ms  {rec['detail'][:70]}")
            if a.ledger:
                with open(a.ledger, "a", encoding="utf-8") as fh:
                    fh.write(_json.dumps({"op": "coverage", **rec}) + "\n")
            if a.interval:
                _time.sleep(a.interval)

    ok = [r for r in rows if r["class"] == "ok"]
    by_class: dict[str, int] = {}
    for r in rows:
        by_class[r["class"]] = by_class.get(r["class"], 0) + 1
    print(f"\ncoverage: {len(ok)}/{len(rows)} reachable ({100*len(ok)/len(rows):.1f}%)")
    for cls, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
        print(f"  {cls:<12}{n}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as fh:
            _json.dump({"base": a.base, "total": len(rows), "reachable": len(ok),
                        "by_class": by_class, "rows": rows}, fh, indent=1)
        print(f"wrote {os.path.abspath(a.out)}")
    if len(ok) < len(rows):
        print("\nNot 'absent'. Each non-ok row is an unreachable id through THIS route,")
        print("with the error that proves it. Change route or class, do not stop here.")
    return 0 if ok else 1


def cmd_probe(a) -> int:
    """Delegate the identity gate to heist.py so there is one implementation."""
    here = os.path.dirname(os.path.abspath(__file__))
    args = [sys.executable, os.path.join(here, "heist.py"), "triage",
            "--base", a.base, "--model", a.model, "--ledger", a.ledger]
    if a.key:
        args += ["--key", a.key]
    if a.product:
        args += ["--product", a.product]
    import subprocess
    return subprocess.call(args)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("catalog")
    c.add_argument("--base", required=True, help="API base, e.g. https://host/v1")
    c.add_argument("--key", default=os.getenv("HEIST_KEY"))
    c.add_argument("--out", default=None)
    c.add_argument("--timeout", type=float, default=40.0)
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_catalog)

    d = sub.add_parser("diff")
    d.add_argument("--catalog", required=True)
    d.add_argument("--sinks", required=True)
    d.add_argument("--all-catalog", action="store_true")
    d.set_defaults(fn=cmd_diff)

    g = sub.add_parser("grep")
    g.add_argument("--catalog", required=True)
    g.add_argument("pattern")
    g.set_defaults(fn=cmd_grep)

    cov = sub.add_parser("coverage")
    cov.add_argument("--catalog", required=True)
    cov.add_argument("--base", default=None)
    cov.add_argument("--key", default=os.getenv("HEIST_KEY"))
    cov.add_argument("--name", default=None, help="label for the single --base route")
    cov.add_argument("--routes", default=None, help="JSON list of {name,base,key} to merge")
    cov.add_argument("--retest", action="store_true", help="probe ids already answered")
    cov.add_argument("--limit", type=int, default=0, help="probe only the first N ids")
    cov.add_argument("--only", default="", help="comma list of ids to probe")
    cov.add_argument("--concurrency", type=int, default=2)
    cov.add_argument("--interval", type=float, default=0.0)
    cov.add_argument("--timeout", type=float, default=60.0)
    cov.add_argument("--ledger", default="state/ledger.jsonl")
    cov.add_argument("--out", default=None)
    cov.set_defaults(fn=cmd_coverage)

    p = sub.add_parser("probe")
    p.add_argument("--catalog", default=None, help="unused; kept for symmetry")
    p.add_argument("--base", required=True)
    p.add_argument("--key", default=os.getenv("HEIST_KEY"))
    p.add_argument("--model", required=True)
    p.add_argument("--product", default=None)
    p.add_argument("--ledger", default="state/ledger.jsonl")
    p.set_defaults(fn=cmd_probe)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        import os as _os
        _os._exit(0)