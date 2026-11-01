#!/usr/bin/env python3
"""Record a page's network traffic over Chrome DevTools Protocol.

For a browser-only target this is the cheapest complete surface map: no proxy,
no certificate, no OS config — the browser is already the trusted client.

    # list targets
    python cdp_capture.py --port 9222 --list

    # capture 20s of an already-open page
    python cdp_capture.py --port 9222 --out artifacts/cdp.jsonl --duration 20

    # reload first, then capture
    python cdp_capture.py --port 9222 --out artifacts/cdp.jsonl --reload

    # attach to an Electron main/renderer target exposed on a fixed ws url
    python cdp_capture.py --ws ws://127.0.0.1:9222/devtools/page/ABC --duration 10

Pair with a real client launch:
    chrome --remote-debugging-port=9222 --user-data-dir=<tmp> \\
           --disable-features=IsolateOrigins,site-per-process https://target

Notes that matter:
  * Network.getResponseBody only works while the request context is alive; fetch
    it on loadingFinished, not later.
  * `--inject-header 'x-debug: 1'` uses Fetch, which rewrites requests — the
    capture is then no longer a faithful record. Use it only for auth probes and
    say so in the ledger.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
import time
import urllib.request

try:
    import websockets
except ImportError:
    print("need websockets: pip install websockets", file=sys.stderr)
    raise SystemExit(2)

SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token"}
BODY_LIMIT = 262_144


def http_json(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


def list_targets(port: int):
    targets = http_json(f"http://127.0.0.1:{port}/json/list")
    pages = [t for t in targets if t.get("type") in {"page", "webview", "other"}]
    for t in pages:
        print(f"{t['type']:<8} {t.get('title','')[:40]:<42} {t['url'][:70]}")
        print(f"         ws={t['webSocketDebuggerUrl']}")
    return pages


def redact(headers: dict) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in SECRET_HEADERS:
            out[k] = f"<redacted {len(v)}B sha={hashlib.sha256(str(v).encode()).hexdigest()[:12]}>"
        else:
            out[k] = v
    return out


async def capture(ws_url: str, out_path: str, duration: float, reload_first: bool,
                  inject: list[str], quiet: bool) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    fh = open(out_path, "a", encoding="utf-8")
    requests: dict[str, dict] = {}
    pending: dict[int, str] = {}       # command id -> requestId awaiting a body
    msg_id = 0

    def emit(rec: dict) -> None:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()
        if not quiet:
            print(f"[cdp] {rec.get('status','---')} {rec.get('method','?')} "
                  f"{str(rec.get('url',''))[:120]}")

    async with websockets.connect(ws_url, max_size=None) as ws:
        async def send(method: str, params: dict | None = None) -> None:
            nonlocal msg_id
            msg_id += 1
            await ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))

        await send("Network.enable", {"maxTotalBufferSize": 20_000_000,
                                      "maxResourceBufferSize": 5_000_000})
        await send("Page.enable")
        if inject:
            headers = {}
            for raw in inject:
                k, _, v = raw.partition(":")
                headers[k.strip()] = v.strip()
            await send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
            if not quiet:
                print(f"[cdp] injecting headers: {list(headers)}")
        if reload_first:
            await send("Page.reload", {"ignoreCache": False})

        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.time()))
            except asyncio.TimeoutError:
                break
            msg = json.loads(raw)
            method = msg.get("method")

            if method == "Fetch.requestPaused":
                rid = msg["params"]["requestId"]
                await send("Fetch.continueRequest", {"requestId": rid, "headers": [
                    {"name": k, "value": v} for k, v in headers.items()] +
                    [{"name": k, "value": v} for k, v in msg["params"]["request"]["headers"].items()
                     if k.lower() not in {h.lower() for h in headers}]})
                continue

            if method == "Network.requestWillBeSent":
                p = msg["params"]
                r = p["request"]
                requests[p["requestId"]] = {
                    "ts": round(p.get("timestamp", time.time()), 3),
                    "method": r["method"],
                    "url": r["url"],
                    "headers": redact(r.get("headers")),
                    "post_data": (r.get("postData") or "")[:BODY_LIMIT] or None,
                    "type": p.get("type"),
                }
                continue

            if method == "Network.responseReceived":
                p = msg["params"]
                rec = requests.setdefault(p["requestId"], {"url": p["response"]["url"]})
                rec["status"] = p["response"]["status"]
                rec["resp_headers"] = redact(p["response"].get("headers"))
                rec["mime"] = p["response"].get("mimeType")
                rec["from_disk_cache"] = p["response"].get("fromDiskCache", False)
                continue

            if "id" in msg and msg["id"] in pending:
                rid = pending.pop(msg["id"])
                rec = requests.pop(rid, None)
                if rec is not None:
                    result = msg.get("result") or {}
                    body = result.get("body")
                    if result.get("base64Encoded") and body:
                        rec["resp_body"] = "base64:" + body[:BODY_LIMIT]
                    else:
                        rec["resp_body"] = (body or "")[:BODY_LIMIT]
                    rec["body_error"] = msg.get("error")
                    emit(rec)
                continue

            if method == "Network.webSocketCreated":
                p_ = msg["params"]
                emit({"type": "ws-open", "url": p_.get("url"),
                      "request_method": "WS", "headers": {}})
                continue

            if method in ("Network.webSocketFrameSent", "Network.webSocketFrameReceived"):
                p_ = msg["params"]
                inner = p_.get("response") or {}
                payload = (inner.get("payloadData") or "")[:BODY_LIMIT]
                emit({"type": "ws-frame",
                      "direction": "s2c" if method.endswith("Received") else "c2s",
                      "url": requests.get(p_.get("requestId"), {}).get("url"),
                      "opcode": inner.get("opcode"),
                      "payload": payload,
                      "payload_len": len(inner.get("payloadData") or "")})
                continue

            if method == "Network.loadingFinished":
                rid = msg["params"]["requestId"]
                msg_id += 1
                pending[msg_id] = rid
                try:
                    await ws.send(json.dumps({"id": msg_id,
                                              "method": "Network.getResponseBody",
                                              "params": {"requestId": rid}}))
                except Exception:  # noqa: BLE001
                    rec = requests.pop(rid, None)
                    if rec is not None:
                        emit(rec)
                continue

    fh.close()
    print(f"\n[cdp] wrote {os.path.abspath(out_path)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--ws", default=None, help="direct websocket debugger url")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--out", default="artifacts/cdp.jsonl")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--reload", action="store_true")
    ap.add_argument("--inject-header", action="append", default=[])
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    if a.list:
        list_targets(a.port)
        return 0

    ws_url = a.ws
    if not ws_url:
        pages = http_json(f"http://127.0.0.1:{a.port}/json/list")
        pages = [t for t in pages if t.get("type") in {"page", "webview"}]
        if not pages:
            print("no page target; pass --ws explicitly", file=sys.stderr)
            return 3
        ws_url = pages[0]["webSocketDebuggerUrl"]
        print(f"[cdp] attaching {pages[0]['url'][:80]}")

    asyncio.run(capture(ws_url, a.out, a.duration, a.reload, a.inject_header, a.quiet))
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
