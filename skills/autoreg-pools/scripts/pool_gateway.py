#!/usr/bin/env python3
"""Minimal account-pool gateway: accounts.jsonl -> one OpenAI-compatible endpoint.

    python pool_gateway.py --accounts accounts.jsonl --upstream https://api.vendor/v1

accounts.jsonl, one JSON object per line:
    {"alias":"a1","key":"sk-...","state":"ok"}          # simplest form
    {"alias":"a2","key":"sk-...","state":"ok","cooldown_until":0}

Endpoints: /v1/models (from --models or first upstream probe), /v1/chat/completions
(streaming and non-streaming, relayed chunk-for-chunk), /healthz, /pool.

The point of the file is the rotation rule: rotate on the error the upstream actually
returns, never on a timer. Everything else is ordinary proxying.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from typing import Any

import httpx

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response, StreamingResponse
except ImportError:
    import sys as _sys
    _sys.stderr.write("pool_gateway.py needs fastapi + uvicorn: pip install fastapi uvicorn\n")
    raise SystemExit(2)

app = FastAPI(title="pool-gateway")
STATE: dict[str, Any] = {"accounts": [], "lock": threading.Lock(), "cursor": 0}


def load_accounts(path: str) -> list[dict]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("key"):
                rec.setdefault("state", "ok")
                rec.setdefault("cooldown_until", 0)
                rec.setdefault("errors", 0)
                out.append(rec)
    return out


def pick() -> dict | None:
    with STATE["lock"]:
        accts = STATE["accounts"]
        now = time.time()
        n = len(accts)
        if n == 0:
            return None
        for i in range(n):
            idx = (STATE["cursor"] + i) % n
            a = accts[idx]
            if a["state"] == "ok" and a["cooldown_until"] <= now:
                STATE["cursor"] = (idx + 1) % n
                a["last_used"] = now
                return a
        return None


def penalise(acct: dict, status: int, body: str) -> None:
    """Rotation rule. Cooldowns come from the upstream's own error language."""
    low = body.lower()
    with STATE["lock"]:
        acct["errors"] = acct.get("errors", 0) + 1
        if status == 401 or status == 403:
            acct["state"] = "dead"
            acct["reason"] = f"{status}"
        elif status == 402 or "insufficient" in low or "quota" in low or "credit" in low:
            acct["cooldown_until"] = time.time() + 1800
            acct["reason"] = "quota"
        elif status == 429:
            acct["cooldown_until"] = time.time() + 10 * min(6, acct["errors"])
            acct["reason"] = "rate"
        else:
            acct["cooldown_until"] = time.time() + 5
            acct["reason"] = f"{status}"


def mark_ok(acct: dict) -> None:
    with STATE["lock"]:
        acct["errors"] = 0
        acct["state"] = "ok"


@app.get("/healthz")
def healthz():
    with STATE["lock"]:
        accts = STATE["accounts"]
        now = time.time()
        return {
            "accounts": len(accts),
            "available": sum(1 for a in accts if a["state"] == "ok" and a["cooldown_until"] <= now),
            "dead": sum(1 for a in accts if a["state"] == "dead"),
            "upstream": STATE.get("upstream"),
        }


@app.get("/pool")
def pool():
    with STATE["lock"]:
        return {"accounts": [
            {k: a.get(k) for k in ("alias", "state", "cooldown_until", "errors", "last_used")}
            for a in STATE["accounts"]
        ]}


@app.get("/v1/models")
def models():
    return {"object": "list", "data": [{"id": m, "object": "model"} for m in STATE["models"]]}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.body()
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return JSONResponse({"error": {"message": "invalid json"}}, status_code=400)

    stream = bool(payload.get("stream"))
    url = STATE["upstream"].rstrip("/") + "/chat/completions"

    for _attempt in range(max(1, len(STATE["accounts"]))):
        acct = pick()
        if acct is None:
            return JSONResponse(
                {"error": {"message": "no account available", "type": "pool_exhausted"}},
                status_code=429)
        headers = {"authorization": f"Bearer {acct['key']}", "content-type": "application/json"}
        try:
            if stream:
                client = httpx.Client(timeout=httpx.Timeout(300, read=300))
                req = client.build_request("POST", url, json=payload, headers=headers)
                resp = client.send(req, stream=True)
                if resp.status_code >= 400:
                    text = resp.read().decode("utf-8", "replace")
                    penalise(acct, resp.status_code, text)
                    resp.close()
                    client.close()
                    continue
                mark_ok(acct)

                def relay(r=resp, c=client):
                    try:
                        for chunk in r.iter_raw():
                            yield chunk
                    finally:
                        r.close()
                        c.close()

                return StreamingResponse(relay(), media_type="text/event-stream",
                                         headers={"cache-control": "no-cache"})

            resp = httpx.post(url, json=payload, headers=headers, timeout=300)
            if resp.status_code >= 400:
                penalise(acct, resp.status_code, resp.text)
                continue
            mark_ok(acct)
            return Response(resp.content, status_code=resp.status_code,
                            media_type=resp.headers.get("content-type", "application/json"))
        except httpx.RequestError as exc:
            penalise(acct, 0, type(exc).__name__)

    return JSONResponse({"error": {"message": "all accounts failed", "type": "pool_exhausted"}},
                        status_code=429)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--accounts", default="accounts.jsonl")
    ap.add_argument("--upstream", required=True, help="OpenAI-compatible base, no /chat/completions")
    ap.add_argument("--models", default="", help="comma list; else probed from upstream")
    ap.add_argument("--port", type=int, default=8100)
    a = ap.parse_args()

    STATE["accounts"] = load_accounts(a.accounts)
    STATE["upstream"] = a.upstream
    if a.models:
        STATE["models"] = [m.strip() for m in a.models.split(",") if m.strip()]
    else:
        try:
            r = httpx.get(a.upstream.rstrip("/") + "/models", timeout=10)
            STATE["models"] = [m["id"] for m in r.json().get("data", [])]
        except Exception:  # noqa: BLE001
            STATE["models"] = []

    print(f"[pool] {len(STATE['accounts'])} accounts, models={STATE['models']}")
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())