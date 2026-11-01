"""mitmproxy addon: capture flows to JSONL, redacted, bounded.

Run:
    mitmdump -s capture.py --set capture_out=artifacts/flows.jsonl \
             --set capture_filter='*/api/*' -p 8080

Or programmatically:
    mitmdump(['-s', 'capture.py', '-p', '8080', '--set', 'capture_out=flows.jsonl'])

Design:
  * one JSONL record per completed HTTP flow, appended and flushed immediately
  * bodies capped (default 256 KiB) and never truncated silently: `body_truncated`
  * secrets hashed, not stored: authorization/cookie/api-key headers
  * filtering is URL-substring regex, default = everything
  * no upstream rewriting: this is an observer, not a mutator. Injection lives in
    a separate addon so a capture is always a record of what the client sent.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any

try:
    from mitmproxy import ctx, http
except ImportError:  # a missing addon dependency must not read as a broken script
    import sys as _sys
    _sys.stderr.write(
        "capture.py is a mitmproxy addon, not a standalone script.\n"
        "  pip install mitmproxy\n"
        "  mitmdump -s capture.py --set capture_out=artifacts/flows.jsonl -p 8080\n"
        "(proxy.py does the same job with no mitmproxy dependency.)\n")
    raise SystemExit(2)

SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key",
                  "api-key", "proxy-authorization", "x-auth-token",
                  "x-csrf-token", "x-xsrf-token"}


def _h(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _headers(h) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in h.items():
        out[k] = f"<redacted {len(v)}B {_h(v)}>" if k.lower() in SECRET_HEADERS else v
    return out


def _body(content: bytes, limit: int) -> tuple[str | None, bool]:
    if content is None:
        return None, False
    truncated = len(content) > limit
    chunk = content[:limit]
    try:
        return chunk.decode("utf-8"), truncated
    except UnicodeDecodeError:
        return "base64:" + __import__("base64").b64encode(chunk).decode("ascii"), truncated


class Capture:
    def __init__(self) -> None:
        self.path: str = "flows.jsonl"
        self.filter = re.compile(r".*")
        self.limit = 262_144
        self.count = 0

    def load(self, loader) -> None:
        loader.add_option("capture_out", str, "flows.jsonl", "JSONL output path")
        loader.add_option("capture_filter", str, "", "URL regex; empty = all")
        loader.add_option("capture_body_limit", int, 262_144, "max bytes per body")
        loader.add_option("capture_quiet", bool, False, "do not log each flow")

    def running(self) -> None:
        self.path = ctx.options.capture_out
        self.limit = ctx.options.capture_body_limit
        self.filter = re.compile(ctx.options.capture_filter or r".*")
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        ctx.log.info(f"[capture] -> {os.path.abspath(self.path)}")

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        if not self.filter.search(url):
            return
        req = flow.request
        res = flow.response
        req_body, req_trunc = _body(req.get_content(strict=False), self.limit)
        res_body, res_trunc = _body(res.get_content(strict=False), self.limit)
        record: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(flow.timestamp_start)),
            "method": req.method,
            "url": url,
            "host": req.pretty_host,
            "path": req.path,
            "status": res.status_code,
            "req_headers": _headers(req.headers),
            "req_body": req_body,
            "req_body_truncated": req_trunc,
            "resp_headers": _headers(res.headers),
            "resp_body": res_body,
            "resp_body_truncated": res_trunc,
            "duration_ms": int((flow.timestamp_end - flow.timestamp_start) * 1000)
            if flow.timestamp_end else None,
            "tls": req.scheme == "https",
            "client_conn": f"{flow.client_conn.peername[0]}:{flow.client_conn.peername[1]}"
            if flow.client_conn.peername else None,
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.count += 1
        if not ctx.options.capture_quiet:
            ctx.log.info(f"[capture] {req.method} {res.status_code} {url[:140]}")


addons = [Capture()]