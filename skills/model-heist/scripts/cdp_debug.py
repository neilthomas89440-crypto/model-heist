#!/usr/bin/env python3
"""Set a breakpoint in a live page and read the state that produced a request.

This is the JS-lane workhorse: when a request carries a signature, nonce, or token,
you do not guess the algorithm — you stop where it is built and read the arguments,
the locals, and the stack.

    # 1. what is there
    python cdp_debug.py --port 9222 --list

    # 2. break on a URL+line, reload, capture the first pause
    python cdp_debug.py --port 9222 --bp-url sign.js:41 --reload --out artifacts/pause.jsonl

    # 3. break on a global function by name, then evaluate in the paused frame
    python cdp_debug.py --port 9222 --bp-func encryptPayload --reload \
        --eval "JSON.stringify(arguments)"

    # 4. break on the XHR/fetch call itself (no source knowledge needed)
    python cdp_debug.py --port 9222 --bp-xhr --reload --duration 40

Output: one JSON record per pause with call frames, scope variables (bounded),
and any --eval result. Nothing is written to disk from the page except that record.

Design notes
    * `Debugger.setBreakpointByUrl` needs a url fragment + 0-based line; if the page
      has no source map, get the line from the stack in a Network capture or from the
      script's `Debugger.scriptParsed` url.
    * `setBreakpointOnFunctionCall` works on already-resolved functions, so evaluate
      the name first; if it is undefined the page has not created it yet.
    * Pauses are resumed automatically after the capture unless --hold is set.
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

SECRET_KEYS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token"}
MAX_SCOPE_ITEMS = 40
MAX_VALUE_CHARS = 400


def http_json(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


def redact_headers(h: dict) -> dict:
    out = {}
    for k, v in (h or {}).items():
        if k.lower() in SECRET_KEYS:
            out[k] = f"<redacted {len(str(v))}B sha={hashlib.sha256(str(v).encode()).hexdigest()[:12]}>"
        else:
            out[k] = v
    return out


class Probe:
    def __init__(self, ws_url: str, out_path: str, *, bp_url: str | None, bp_func: str | None,
                 bp_xhr: bool, eval_expr: str | None, hold: bool, quiet: bool):
        self.ws_url = ws_url
        self.out_path = out_path
        self.bp_url = bp_url
        self.bp_func = bp_func
        self.bp_xhr = bp_xhr
        self.eval_expr = eval_expr
        self.hold = hold
        self.quiet = quiet
        self.id = 0
        self.pending: dict[int, str] = {}
        self.pauses = 0
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        self.fh = open(out_path, "a", encoding="utf-8")

    def emit(self, rec: dict) -> None:
        rec["ts"] = round(time.time(), 3)
        self.fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.fh.flush()
        if not self.quiet:
            print(f"[dbg] {rec.get('type')} {rec.get('url','')[:80]} {rec.get('function','')}")

    async def send(self, ws, method: str, params: dict | None = None, wait: bool = False,
                   timeout: float = 10.0):
        self.id += 1
        mid = self.id
        if wait:
            self.pending[mid] = method
        await ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        return mid

    async def install(self, ws) -> None:
        await self.send(ws, "Debugger.enable")
        await self.send(ws, "Runtime.enable")
        await self.send(ws, "Page.enable")
        if self.bp_url:
            frag, _, line = self.bp_url.rpartition(":")
            if not frag:
                frag, line = self.bp_url, "0"
            await self.send(ws, "Debugger.setBreakpointByUrl",
                            {"urlRegex": f".*{frag}.*", "lineNumber": int(line)})
        if self.bp_func:
            src = f"typeof {self.bp_func} === 'function'"
            mid = await self.send(ws, "Runtime.evaluate", {"expression": src}, wait=True)
            deadline = time.time() + 5
            while mid in self.pending and time.time() < deadline:
                await asyncio.sleep(0.05)
        if self.bp_xhr:
            await self.send(ws, "Fetch.enable", {"patterns": [
                {"urlPattern": "*", "requestStage": "Request"}]})

    async def on_paused(self, ws, params: dict) -> None:
        self.pauses += 1
        frames = []
        for fr in params.get("callFrames", [])[:12]:
            loc = fr.get("location", {})
            frames.append({
                "function": fr.get("functionName") or "(anonymous)",
                "url": fr.get("url"),
                "line": loc.get("lineNumber"),
                "column": loc.get("columnNumber"),
                "scope": fr.get("scopeChain", [{}])[0].get("type") if fr.get("scopeChain") else None,
            })
        rec = {"type": "pause", "reason": params.get("reason"),
               "hit_breakpoints": params.get("hitBreakpoints", []),
               "frames": frames}

        top = (params.get("callFrames") or [{}])[0]
        frame_id = top.get("frameId")
        props: dict[str, str] = {}
        for scope in (top.get("scopeChain") or [])[:3]:
            oid = scope.get("object", {}).get("objectId")
            if not oid:
                continue
            mid = await self.send(ws, "Runtime.getProperties",
                                  {"objectId": oid, "ownProperties": True})
            # collect the reply inline: this is the whole point of pausing
            deadline = time.time() + 8
            result = None
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=max(0.05, deadline - time.time()))
                except asyncio.TimeoutError:
                    break
                msg = json.loads(raw)
                if msg.get("id") == mid:
                    result = msg.get("result")
                    break
                await self.dispatch(ws, msg)
            if not result:
                continue
            for p in (result.get("result") or [])[:MAX_SCOPE_ITEMS]:
                val = p.get("value", {})
                repr_ = (val.get("description") or val.get("value") or val.get("type") or "")
                props[f"{scope.get('type','scope')}.{p.get('name')}"] = str(repr_)[:MAX_VALUE_CHARS]
        rec["variables"] = props

        if self.eval_expr and frame_id:
            mid = await self.send(ws, "Debugger.evaluateOnCallFrame",
                                  {"callFrameId": frame_id, "expression": self.eval_expr,
                                   "returnByValue": True})
            deadline = time.time() + 8
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=max(0.05, deadline - time.time()))
                except asyncio.TimeoutError:
                    break
                msg = json.loads(raw)
                if msg.get("id") == mid:
                    res = msg.get("result", {}).get("result", {})
                    rec["eval"] = str(res.get("value") or res.get("description") or "")[:2000]
                    break
                await self.dispatch(ws, msg)

        header = top.get("url") or ""
        rec["url"] = header
        self.emit(rec)
        if not self.hold:
            await self.send(ws, "Debugger.resume")

    async def dispatch(self, ws, msg: dict) -> None:
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "Debugger.paused":
            await self.on_paused(ws, params)
        elif method == "Fetch.requestPaused":
            rid = params.get("requestId")
            req = params.get("request") or {}
            body = req.get("postData")
            self.emit({"type": "xhr", "method": req.get("method"), "url": req.get("url"),
                       "headers": redact_headers(req.get("headers")),
                       "post_data": (body or "")[:2000],
                       "initiator": (params.get("resourceType") or "")})
            await self.send(ws, "Fetch.continueRequest", {"requestId": rid})

    async def run(self, duration: float, reload_first: bool) -> None:
        async with websockets.connect(self.ws_url, max_size=None) as ws:
            await self.install(ws)
            if reload_first:
                await self.send(ws, "Page.reload", {"ignoreCache": False})
            deadline = time.time() + duration
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.time()))
                except asyncio.TimeoutError:
                    break
                await self.dispatch(ws, json.loads(raw))
        self.fh.close()
        print(f"\n[dbg] pauses={self.pauses} -> {os.path.abspath(self.out_path)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--ws", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--out", default="artifacts/pauses.jsonl")
    ap.add_argument("--bp-url", default=None, help="script-url-fragment:line (0-based)")
    ap.add_argument("--bp-func", default=None, help="global function name to break on")
    ap.add_argument("--bp-xhr", action="store_true", help="intercept every request/response before it is sent")
    ap.add_argument("--eval", dest="eval_expr", default=None, help="expression evaluated in the top frame")
    ap.add_argument("--reload", action="store_true")
    ap.add_argument("--hold", action="store_true", help="stay paused after capture")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    if a.list:
        pages = [t for t in http_json(f"http://127.0.0.1:{a.port}/json/list")
                 if t.get("type") in {"page", "webview"}]
        for t in pages:
            print(f"{t.get('title','')[:40]:<42} {t['url'][:70]}")
            print(f"    ws={t['webSocketDebuggerUrl']}")
        if not pages:
            print("no page targets; start chrome with --remote-debugging-port=<port>")
        return 0

    ws_url = a.ws
    if not ws_url:
        pages = [t for t in http_json(f"http://127.0.0.1:{a.port}/json/list")
                 if t.get("type") in {"page", "webview"}]
        if not pages:
            print("no page target", file=sys.stderr)
            return 3
        ws_url = pages[0]["webSocketDebuggerUrl"]

    if not (a.bp_url or a.bp_func or a.bp_xhr):
        print("no breakpoint requested (--bp-url / --bp-func / --bp-xhr)", file=sys.stderr)
        return 2

    probe = Probe(ws_url, a.out, bp_url=a.bp_url, bp_func=a.bp_func, bp_xhr=a.bp_xhr,
                  eval_expr=a.eval_expr, hold=a.hold, quiet=a.quiet)
    asyncio.run(probe.run(a.duration, a.reload))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        import os as _os
        _os._exit(0)