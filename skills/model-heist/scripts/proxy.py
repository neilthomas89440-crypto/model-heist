#!/usr/bin/env python3
"""Self-contained MITM HTTP/HTTPS proxy with JSONL capture.

Why this exists: `mitmdump` is a dependency chain (mitmproxy_rs local redirector,
Rust wheels, version-gated Python) that silently no-ops on some Windows/Python
combinations. This file depends on nothing but stdlib + `cryptography`, so the
capture stack is guaranteed to run wherever the skill runs.

    python proxy.py --port 8080 --ca-dir state/ca --out artifacts/flows.jsonl
    # then point the client at http://127.0.0.1:8080
    # install <ca-dir>/ca.pem into the OS/browser trust store for HTTPS

Behaviour:
  * dynamic leaf certificates signed by one local CA, cached per host
  * streams bodies to the client as they arrive (SSE/chat APIs stay live) while
    capturing up to --body-limit bytes
  * redacts Authorization/Cookie/api-key headers in the record, keeps sha256
  * one JSONL line per request/response pair, flushed immediately

Not implemented on purpose: HTTP/2 (client and upstream use HTTP/1.1), QUIC,
WebSocket framing beyond raw byte pass-through capture.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import socket
import ssl
import sys
import threading
import time
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("need cryptography: pip install cryptography", file=sys.stderr)
    raise SystemExit(2)

SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key",
                  "proxy-authorization", "x-auth-token", "x-csrf-token"}
MAX_HEADER_BYTES = 64 * 1024
CAP_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ CA stuff

class CertAuthority:
    def __init__(self, ca_dir: str, organization: str = "model-heist local CA"):
        os.makedirs(ca_dir, exist_ok=True)
        self.dir = ca_dir
        self.key_path = os.path.join(ca_dir, "ca.key")
        self.cert_path = os.path.join(ca_dir, "ca.pem")
        self.org = organization
        self._leaf_cache: dict[str, tuple[bytes, bytes]] = {}
        self._lock = threading.Lock()
        self.key, self.cert = self._load_or_create()

    def _load_or_create(self):
        if os.path.exists(self.key_path) and os.path.exists(self.cert_path):
            with open(self.key_path, "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
            with open(self.cert_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            return key, cert

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self.org} root"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256())
        )
        with open(self.key_path, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
        os.chmod(self.key_path, 0o600)
        with open(self.cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        return key, cert

    def leaf(self, host: str) -> tuple[bytes, bytes]:
        with self._lock:
            hit = self._leaf_cache.get(host)
            if hit:
                return hit
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            try:
                san = x509.IPAddress(__import__("ipaddress").ip_address(host))
            except ValueError:
                san = x509.DNSName(host)
            leaf = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                .issuer_name(self.cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                               critical=False)
                .sign(self.key, hashes.SHA256())
            )
            key_pem = key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.TraditionalOpenSSL,
                                        serialization.NoEncryption())
            cert_pem = leaf.public_bytes(serialization.Encoding.PEM)
            if len(self._leaf_cache) > 512:
                self._leaf_cache.clear()
            self._leaf_cache[host] = (key_pem, cert_pem)
            return key_pem, cert_pem

    def server_context(self, host: str) -> ssl.SSLContext:
        key_pem, cert_pem = self.leaf(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert_chain(cert_pem, key_pem))
        return ctx

    def _cert_chain(self, cert_pem: bytes, key_pem: bytes) -> str:
        base = os.path.join(self.dir, "_chain")
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, f"leaf-{hashlib.sha256(cert_pem).hexdigest()[:16]}.pem")
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(cert_pem + b"\n" + key_pem)
        return path


# ------------------------------------------------------------------ helpers

def read_headers(sock) -> tuple[bytes, dict[str, str]]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed in headers")
        buf += chunk
        if len(buf) > MAX_HEADER_BYTES:
            raise ConnectionError("header overflow")
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    first = lines[0].decode("latin-1")
    headers: dict[str, str] = {}
    order: list[str] = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        key = k.decode("latin-1").strip()
        headers[key] = v.decode("latin-1").strip()
        order.append(key)
    return first.encode("latin-1"), headers, rest


def redact(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in SECRET_HEADERS:
            out[k] = f"<redacted {len(v)}B sha256:{hashlib.sha256(v.encode()).hexdigest()[:16]}>"
        else:
            out[k] = v
    return out


def parse_ws_frame(buf: bytes):
    """Parse one WebSocket frame from `buf`. Returns (frame|None, consumed).

    Header-only facts (opcode, fin, length) plus a bounded payload. Masked frames
    (client→server) are unmasked so the record is readable.
    """
    if len(buf) < 2:
        return None, 0
    b0, b1 = buf[0], buf[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    idx = 2
    if length == 126:
        if len(buf) < 4:
            return None, 0
        length = int.from_bytes(buf[2:4], "big")
        idx = 4
    elif length == 127:
        if len(buf) < 10:
            return None, 0
        length = int.from_bytes(buf[2:10], "big")
        idx = 10
    mask = b""
    if masked:
        if len(buf) < idx + 4:
            return None, 0
        mask = buf[idx:idx + 4]
        idx += 4
    if len(buf) < idx + length:
        return None, 0
    payload = buf[idx:idx + length]
    if masked and mask:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    return {"fin": fin, "opcode": opcode, "masked": masked, "length": length,
            "payload": payload}, idx + length


def dechunk(data: bytes) -> bytes:
    """Decode a (possibly truncated) chunked body. Returns what it could decode."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        end = min(start + size, n)
        out += data[start:end]
        i = end + 2
    return bytes(out)


def body_prefix(data: bytes, limit: int) -> tuple[str | None, bool]:
    if not data:
        return None, False
    cut = data[:limit]
    try:
        return cut.decode("utf-8"), len(data) > limit
    except UnicodeDecodeError:
        return "base64:" + base64.b64encode(cut).decode(), len(data) > limit


class Recorder:
    def __init__(self, path: str):
        self.path = path
        self.count = 0
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def write(self, rec: dict) -> None:
        with CAP_LOCK:
            self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._fh.flush()
            self.count += 1
            if self.count % 25 == 0:
                print(f"[proxy] {self.count} flows captured", flush=True)


class Proxy:
    def __init__(self, port: int, ca: CertAuthority, rec: Recorder,
                 body_limit: int, verbose: bool):
        self.port = port
        self.ca = ca
        self.rec = rec
        self.body_limit = body_limit
        self.verbose = verbose
        self.up_ctx = ssl.create_default_context()
        self.up_ctx.check_hostname = False
        self.up_ctx.verify_mode = ssl.CERT_NONE  # capture tool: never fail on upstream TLS

    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(128)
        print(f"[proxy] listening 0.0.0.0:{self.port}  CA={self.ca.cert_path}")
        print(f"[proxy] capture -> {os.path.abspath(self.rec.path)}")
        while True:
            try:
                client, addr = srv.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(client, addr), daemon=True).start()

    # -- connection handling ------------------------------------------------
    def handle(self, client: socket.socket, addr) -> None:
        try:
            first, headers, leftover = read_headers(client)
            line = first.decode("latin-1")
            method, target, _ver = (line.split(" ", 2) + ["", ""])[:3]
            if method.upper() == "CONNECT":
                self.do_connect(client, target)
            else:
                self.do_plain(client, method, target, headers, first, leftover)
        except Exception as exc:  # noqa: BLE001
            if self.verbose:
                print(f"[proxy] {addr} error: {type(exc).__name__}: {exc}", flush=True)
        finally:
            try:
                client.close()
            except OSError:
                pass

    def do_connect(self, client: socket.socket, target: str, leftover: bytes = b"") -> None:
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        ctx = self.ca.server_context(host)
        try:
            tls_client = ctx.wrap_socket(client, server_side=True)
        except ssl.SSLError as exc:
            if self.verbose:
                print(f"[proxy] client TLS failed for {host}: {exc}", flush=True)
            return
        # loop for keep-alive
        while True:
            try:
                first, headers, leftover = read_headers(tls_client)
            except (ConnectionError, OSError):
                return
            line = first.decode("latin-1")
            method, tpath, _ = (line.split(" ", 2) + ["", ""])[:3]
            netloc = host if port == 443 else f"{host}:{port}"
            url = f"https://{netloc}{tpath}"
            if not self.forward(tls_client, host, port, method, tpath, headers, url,
                                scheme_tls=True, req_prefetch=leftover):
                return

    def do_plain(self, client: socket.socket, method: str, target: str,
                 headers: dict[str, str], first: bytes, leftover: bytes = b"") -> None:
        if target.startswith("http://"):
            rest = target[7:]
            host, _, path = rest.partition("/")
            path = "/" + path
            hostname, _, port_s = host.partition(":")
            port = int(port_s or 80)
        else:  # origin-form through a transparent setup
            host_hdr = headers.get("Host", "")
            hostname, _, port_s = host_hdr.partition(":")
            port = int(port_s or 80)
            path = target
        url = f"http://{hostname}:{port}{path}"
        self.forward(client, hostname, port, method, path, headers, url,
                     scheme_tls=False, req_prefetch=leftover)

    # -- one request/response pair -----------------------------------------
    def forward(self, client, host, port, method, path, headers, url,
                scheme_tls: bool, req_prefetch: bytes = b"") -> bool:
        started = time.time()
        length = int(headers.get("Content-Length") or 0)
        req_body = bytearray(req_prefetch)
        if length and length <= 32 * 1024 * 1024:
            while len(req_body) < length:
                chunk = client.recv(min(65536, length - len(req_body)))
                if not chunk:
                    break
                req_body += chunk

        up = socket.create_connection((host, port), timeout=30)
        try:
            if scheme_tls:
                up = self.up_ctx.wrap_socket(up, server_hostname=host)
            else:
                up = up
            head = [f"{method} {path} HTTP/1.1"]
            sent: dict[str, str] = {}
            for k, v in headers.items():
                if k.lower() in {"proxy-connection", "connection", "keep-alive"}:
                    continue
                sent[k] = v
            is_upgrade = ("upgrade" in (headers.get("Upgrade", "") or "").lower()
                          or "upgrade" in (headers.get("Connection", "") or "").lower())
            if not is_upgrade:
                sent["Connection"] = "close"
            for k, v in sent.items():
                head.append(f"{k}: {v}")
            up.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + bytes(req_body))

            # Interim 1xx responses (100 Continue, 103 Early Hints) are not the
            # answer: forward them and keep reading until a final status arrives,
            # otherwise the capture records "100" and the real body as payload.
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = up.recv(65536)
                    if not chunk:
                        raise ConnectionError("closed before final response")
                    buf += chunk
                head_bytes, buf = buf.split(b"\r\n\r\n", 1)
                status_line = head_bytes.decode("latin-1")
                first_line = status_line.split("\r\n", 1)[0]
                parts = first_line.split(" ", 2)
                interim = 100 <= (int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0) < 200
                if interim and not first_line.startswith("HTTP/1.1 101"):
                    client.sendall(head_bytes + b"\r\n\r\n")
                    continue
                break
            resp_head = head_bytes
            resp_headers = {}
            for line in status_line.split("\r\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    resp_headers[k.strip()] = v.strip()
            resp_prefetch = buf
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            client.sendall((first_line + "\r\n").encode("latin-1"))
            for k, v in resp_headers.items():
                if k.lower() in {"connection", "keep-alive"}:
                    continue
                client.sendall(f"{k}: {v}\r\n".encode("latin-1"))
            client.sendall(b"\r\n" if status == 101 else b"Connection: close\r\n\r\n")

            # A WebSocket upgrade never has a body: hand the sockets to the frame
            # relay now, or the body loop below blocks until the peer closes.
            if status == 101 and "websocket" in (resp_headers.get("Upgrade", "") or "").lower():
                self.rec.write({
                    "ts": now_iso(), "type": "ws-open", "url": url, "status": 101,
                    "req_headers": redact(headers), "resp_headers": redact(resp_headers),
                })
                if resp_prefetch:
                    client.sendall(resp_prefetch)
                self.ws_relay(client, up, url)
                return False

            captured = bytearray()
            truncated = False
            if resp_prefetch:
                captured += resp_prefetch[: self.body_limit]
                client.sendall(resp_prefetch)
            while True:
                chunk = up.recv(65536)
                if not chunk:
                    break
                if len(captured) < self.body_limit:
                    captured += chunk[: self.body_limit - len(captured)]
                if len(captured) >= self.body_limit:
                    truncated = True
                client.sendall(chunk)

            cap_bytes = bytes(captured)
            if "chunked" in (resp_headers.get("Transfer-Encoding", "") or "").lower():
                cap_bytes = dechunk(cap_bytes)
            rec: dict[str, Any] = {
                "ts": now_iso(),
                "method": method,
                "url": url,
                "host": host,
                "path": path,
                "status": status,
                "req_headers": redact(headers),
                "req_body": body_prefix(bytes(req_body), self.body_limit)[0],
                "req_body_truncated": len(req_body) > self.body_limit,
                "resp_headers": redact(resp_headers),
                "resp_body": body_prefix(cap_bytes, self.body_limit)[0],
                "resp_body_truncated": truncated,
                "duration_ms": int((time.time() - started) * 1000),
                "tls": scheme_tls,
            }
            self.rec.write(rec)
            if self.verbose:
                print(f"[proxy] {status} {method} {url[:110]}", flush=True)
            return False  # one request per connection: simpler, safe for streaming
        finally:
            try:
                up.close()
            except OSError:
                pass


    def ws_relay(self, client, up, url: str) -> None:
        """Relay bytes verbatim and record each complete frame in both directions."""
        stop = threading.Event()

        def pump(src, dst, direction: str) -> None:
            buf = b""
            try:
                while not stop.is_set():
                    data = src.recv(65536)
                    if not data:
                        break
                    try:
                        dst.sendall(data)
                    except OSError:
                        break
                    buf += data
                    while True:
                        frame, consumed = parse_ws_frame(buf)
                        if frame is None or consumed == 0:
                            break
                        buf = buf[consumed:]
                        payload = frame["payload"]
                        text, truncated = body_prefix(payload, self.body_limit)
                        self.rec.write({
                            "ts": now_iso(), "type": "ws-frame", "url": url,
                            "direction": direction, "opcode": frame["opcode"],
                            "fin": frame["fin"], "length": frame["length"],
                            "payload": text, "payload_truncated": truncated,
                        })
            except OSError:
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=pump, args=(client, up, "c2s"), daemon=True)
        t2 = threading.Thread(target=pump, args=(up, client, "s2c"), daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=3600)
        t2.join(timeout=5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ca-dir", default="state/ca")
    ap.add_argument("--out", default="artifacts/flows.jsonl")
    ap.add_argument("--body-limit", type=int, default=262_144)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    ca = CertAuthority(a.ca_dir)
    rec = Recorder(a.out)
    proxy = Proxy(a.port, ca, rec, a.body_limit, a.verbose or True)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[proxy] stopped after {rec.count} flows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())