#!/usr/bin/env python3
"""Fetch a website's JavaScript bundle and emit a recon report.

Stdlib only. This is the static pass for a web-only target: it turns a URL into
a local tree of scripts plus endpoint/model candidates, without a browser.

    python web_bundle.py https://target/ --out reverse/<target>/artifacts/web
    python web_bundle.py https://target/ --with-maps --max-files 400

Output:
    <out>/index.html
    <out>/scripts/<name>-<hash8>.js
    <out>/manifest.json     url -> file, sha256, bytes, status
    <out>/report.json      hosts, api paths, ws URLs, keyword hits, source maps

Then use REA `analyze_web_bundle` / `export_web_scripts` for the graph view.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from html.parser import HTMLParser
from pathlib import Path

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

EXTRA_HEADERS: dict[str, str] = {}
SCRIPT_ATTRS = ("src", "href")
KEYWORDS = (
    "token", "mint", "auth", "session", "apikey", "api_key", "authorization",
    "model", "models", "inference", "completion", "chat", "prompt", "system",
    "tool", "tools", "quota", "credit", "usage", "limit", "plan", "subscription",
    "stream", "websocket", "sourcemap", "debug", "staging", "preview",
)


class Assets(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.styles: list[str] = []
        self.inline: list[str] = []
        self.metas: list[dict[str, str]] = []
        self._buf: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
                self._buf = []
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            href = a.get("href") or ""
            if not href:
                return
            if "stylesheet" in rel:
                self.styles.append(href)
            elif any(x in rel for x in ("preload", "modulepreload", "prefetch")):
                if a.get("as") in ("script", "") or href.endswith(".js") or href.endswith(".mjs"):
                    self.scripts.append(href)
        elif tag == "meta":
            self.metas.append(a)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline.append("".join(self._buf))
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


def fetch(url: str, timeout: float, limit: int) -> tuple[int, bytes, dict, str]:
    headers_out = {
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    headers_out.update(EXTRA_HEADERS)
    req = urllib.request.Request(url, headers=headers_out)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(limit + 1)
            headers = {k.lower(): v for k, v in r.headers.items()}
            enc = headers.get("content-encoding", "").lower()
            if enc == "gzip":
                raw = gzip.decompress(raw)
            elif enc == "deflate":
                raw = zlib.decompress(raw)
            if len(raw) > limit:
                raw = raw[:limit]
            return r.status, raw, headers, r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, b"", {}, url
    except Exception as e:
        return 0, b"", {}, f"{type(e).__name__}: {e}"


def safe_name(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    name = Path(path).name or "index.js"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    h = hashlib.sha256(url.encode()).hexdigest()[:8]
    return f"{name[:80]}-{h}"


def scan(text: str) -> dict:
    trim = "'\"`,;)\\"
    hosts = sorted({m.rstrip(trim) for m in
                    re.findall(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", text)})
    ws = sorted({m.rstrip(trim) for m in
                 re.findall(r"wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", text)})
    paths = sorted(set(re.findall(r"""(?<![\w.])/(?:api|v\d+|graphql|rest|rpc|trpc|socket|ws)/[A-Za-z0-9_./{}$:-]{1,120}""", text)))
    maps = sorted(set(re.findall(r"sourceMappingURL=([^\s*]+)", text)))
    hits: dict[str, int] = {}
    low = text.lower()
    for kw in KEYWORDS:
        n = low.count(kw)
        if n:
            hits[kw] = n
    return {"hosts": hosts, "websockets": ws, "api_paths": paths,
            "source_maps": maps, "keyword_hits": hits}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--out", default="web-bundle")
    ap.add_argument("--timeout", type=float, default=25)
    ap.add_argument("--max-bytes", type=int, default=8_000_000)
    ap.add_argument("--max-files", type=int, default=250)
    ap.add_argument("--with-maps", action="store_true")
    ap.add_argument("--cross-origin", action="store_true")
    ap.add_argument("--header", action="append", default=[],
                    help='extra header, e.g. --header "X-Build: 42"')
    ap.add_argument("--cookie", default="",
                    help='Cookie header value for authenticated pages')
    a = ap.parse_args()

    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            EXTRA_HEADERS[k.strip()] = v.strip()
    if a.cookie:
        EXTRA_HEADERS["Cookie"] = a.cookie

    out = Path(a.out)
    (out / "scripts").mkdir(parents=True, exist_ok=True)
    origin = urllib.parse.urlparse(a.url).netloc

    status, body, headers, final = fetch(a.url, a.timeout, a.max_bytes)
    (out / "headers.json").write_text(json.dumps(headers, indent=1), encoding="utf-8")
    (out / "index.html").write_bytes(body)
    print(f"entry {status} {len(body)} bytes {final}")

    parser = Assets()
    parser.feed(body.decode("utf-8", "replace"))

    urls: list[str] = []
    for src in parser.scripts:
        u = urllib.parse.urljoin(final, src)
        if a.cross_origin or urllib.parse.urlparse(u).netloc == origin:
            urls.append(u)
    seen: set[str] = set()
    urls = [u for u in urls if not (u in seen or seen.add(u))][: a.max_files]

    manifest = [{"url": final, "file": "index.html", "sha256": hashlib.sha256(body).hexdigest(),
                 "bytes": len(body), "status": status}]
    all_text: list[tuple[str, str]] = [(body.decode("utf-8", "replace"), final)]
    for inline in parser.inline:
        all_text.append((inline, final))

    for u in urls:
        st, data, hdrs, _ = fetch(u, a.timeout, a.max_bytes)
        name = safe_name(u)
        rel = f"scripts/{name}"
        (out / rel).write_bytes(data)
        manifest.append({"url": u, "file": rel, "sha256": hashlib.sha256(data).hexdigest(),
                         "bytes": len(data), "status": st,
                         "content_type": hdrs.get("content-type", "")})
        if data:
            all_text.append((data.decode("utf-8", "replace"), u))
        print(f"  {st} {len(data):>9d}  {u[:110]}")
        time.sleep(0.05)

    if a.with_maps:
        for text, base in list(all_text):
            for m in re.findall(r"sourceMappingURL=([^\s*]+)", text):
                mu = urllib.parse.urljoin(base, m)
                st, data, _, _ = fetch(mu, a.timeout, a.max_bytes)
                if st == 200 and data:
                    rel = f"scripts/{safe_name(mu)}.map"
                    (out / rel).write_bytes(data)
                    manifest.append({"url": mu, "file": rel,
                                     "sha256": hashlib.sha256(data).hexdigest(),
                                     "bytes": len(data), "status": st})
                    print(f"  map {len(data):>9d}  {mu[:100]}")

    combined = "\n".join(t for t, _ in all_text)
    report = scan(combined)
    report["source_maps"] = sorted({
        urllib.parse.urljoin(base, m)
        for text, base in all_text
        for m in re.findall(r"sourceMappingURL=([^\s*]+)", text)
    })
    report["build"] = {
        "entry": final,
        "status": status,
        "server": headers.get("server"),
        "build_headers": {k: v for k, v in headers.items()
                          if k.startswith("x-") or k in ("etag", "last-modified")},
        "metas": parser.metas[:40],
        "inline_scripts": len(parser.inline),
        "scripts": len(urls),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    (out / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")

    print(f"\nscripts={len(urls)} bytes={sum(m['bytes'] for m in manifest)} "
          f"hosts={len(report['hosts'])} api_paths={len(report['api_paths'])} "
          f"maps={len(report['source_maps'])}")
    print(f"out={out.resolve()}")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
