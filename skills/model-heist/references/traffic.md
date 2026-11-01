# Traffic interception

Static analysis ends where the client computes something: a signature, a nonce, an
encrypted envelope, a token behind a captcha, a request assembled by a WASM module.
Capture the real thing, then reproduce it.

Rule zero: **a capture you did not write to disk does not exist.** Every command here
writes JSONL with redacted headers and body caps; that file is evidence.

## Pick by target class

| Target | First method | Why not the others |
|---|---|---|
| Web site, SPA, Electron renderer | `cdp_capture.py` (CDP) | no CA, no OS config, sees the exact bytes the page sends, survives HTTP/2 and QUIC |
| Electron **main** process / preload | CDP on the renderer + proxy for main-process traffic | main process is Node; CDP only reaches renderers |
| Native desktop app (Qt, WinForms, Go, Rust, C++) | `proxy.py` + CA in the OS store | no debug surface; TLS is the only seam |
| CLI tool | `proxy.py` via `HTTP(S)_PROXY`, or `SSLKEYLOGFILE` | many CLIs honour env proxies and never touch the OS store |
| Android | `adb reverse` + frida | user CAs are ignored by `targetSdk>=24` apps |
| iOS | jailed: proxy + trust profile; jailbroken: frida | App Store apps that pin need a runtime hook |
| Anything that pins TLS | frida hooks on `SSL_read`/`SSL_write` | proxying fails at handshake; you need plaintext inside the process |

## Browser and Electron — CDP

Launch (or attach to) a debugging port. The port is a full control channel; treat it
as such and never expose it on `0.0.0.0`.

```bash
chrome --remote-debugging-port=9222 --user-data-dir=/tmp/prof \
       --disable-quic https://target
python ~/.agents/skills/model-heist/scripts/cdp_capture.py --port 9222 --list
python ~/.agents/skills/model-heist/scripts/cdp_capture.py --port 9222 \
       --out artifacts/cdp.jsonl --duration 30 --reload
```

Electron: `--remote-debugging-port` works the same way but only exposes renderers.
If the app is packaged, unpack `resources/app.asar` (`npx asar extract`) for the
static pass, and add `--remote-debugging-port=` to its own launcher arguments.

Domains worth knowing beyond `Network`:

| Domain | Use |
|---|---|
| `Network` | request/response bodies, headers, timings, WebSocket frames |
| `Fetch` | intercept and rewrite a request before it leaves — the cheapest auth probe |
| `Page.addScriptToEvaluateOnNewDocument` | install hooks before any page script runs (must be at document-start, or the page's own hooks win) |
| `Runtime.evaluate` | read a live global: an already-minted token, a computed signature, a wasm export |
| `Debugger.setBreakpointOnFunctionCall` | break where the signature is produced, read arguments |
| `Target.setAutoAttach` | capture iframes, workers, service workers — signatures often live in a worker |

`cdp_capture.py --inject-header 'x-debug: 1'` uses `Fetch`; note in the ledger that
the capture is no longer a faithful record when you rewrite.

## Native apps — intercepting proxy

```bash
python ~/.agents/skills/model-heist/scripts/proxy.py \
       --port 8080 --ca-dir state/ca --out artifacts/flows.jsonl
# install state/ca/ca.pem:
#   Windows: certutil -addstore -f "ROOT" state\ca\ca.pem
#   macOS:   security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain state/ca/ca.pem
#   Linux:   cp state/ca/ca.pem /usr/local/share/ca-certificates/heist.crt && update-ca-certificates
```

Then point the client at `127.0.0.1:8080`. Which switch depends on the stack:

| Stack | Proxy switch | Trust store |
|---|---|---|
| Chromium/Electron | `--proxy-server=http://127.0.0.1:8080` | Chromium store (add the CA there) or `--ignore-certificate-errors` |
| WinHTTP / WinINet (.NET, many native apps) | `netsh winhttp set proxy 127.0.0.1:8080` or registry `ProxyServer` | Windows ROOT store |
| Go `net/http` | `HTTPS_PROXY` env | system store on Windows/macOS, CA bundle on Linux |
| Rust `reqwest`/`rustls` | `HTTPS_PROXY` env | `SSL_CERT_FILE` pointing at `ca.pem` |
| Java | `-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080` | `-Djavax.net.ssl.trustStore=state/ca/truststore.jks` |
| .NET `HttpClient` | inherits WinHTTP or explicit `WebProxy` | `ServicePointManager.ServerCertificateValidationCallback` in a debugger, or ROOT store |
| curl | `-x http://127.0.0.1:8080 --noproxy ""` | `--cacert state/ca/ca.pem` (or `-k`) |
| Python `requests` | `HTTPS_PROXY` | `REQUESTS_CA_BUNDLE=state/ca/ca.pem` |

Note the `--noproxy ""` on curl: it bypasses proxies for localhost by default, which
produces the classic "the proxy works but nothing is captured" dead end.

## Certificate pinning

Symptom: the proxy works for one app and the target silently fails to connect, or
connects and returns nothing. Do not conclude "the API is dead". Pinning ladder,
cheapest first:

1. **Client-provided trust knob.** Many apps ship `--ignore-certificate-errors`,
   an env var, or a debug setting. Read the bundle for it (`grep -i "certificate"`).
2. **Older pinning.** Some pin only `SubjectPublicKeyInfo` of a root you can replace,
   or only on non-release builds. Check the build channel.
3. **Frida / runtime hook of the TLS library.** This is the reliable path:

   ```javascript
   // hooks/ssl.js — BoringSSL (Chrome, Flutter iOS/Android, most Rust+OpenSSL apps)
   const SSL_read  = Module.findExportByName(null, 'SSL_read');
   const SSL_write = Module.findExportByName(null, 'SSL_write');
   Interceptor.attach(SSL_read,  { onLeave(r, s) { dump('IN',  r, s); } });
   Interceptor.attach(SSL_write, { onEnter(a)     { dump('OUT', a[1], a[2]); } });
   function dump(tag, r, size) {
     size = size.toInt32();
     if (size <= 0 || size > 1 << 20) return;
     const buf = r.isNull() ? ptr(0) : r;
     if (buf.isNull()) return;
     send({ tag, data: buf.readByteArray(size) });
   }
   ```

   Run with `frida -f target.exe -l hooks/ssl.js --no-pause`. Signature is
   `SSL_read(ssl, buf, num)`; the plaintext is at `buf` on return, and `size` is in
   the first argument register on x64 — read `a[2]` for `SSL_write(ssl, buf, num)`.
4. **Flutter/Dart.** Same BoringSSL symbols live inside `libflutter.so`; locate with
   the module-relative export list rather than a hardcoded offset.
5. **Go binaries.** `crypto/tls` is statically linked and `SSL_read` does not exist.
   Hook Go's `crypto/tls.(*Conn).Read` by symbol, or use `SSLKEYLOGFILE` if the
   build honours it, or patch `InsecureSkipVerify` in memory.
6. **Rust `rustls`.** Hook `rustls::conn::ConnectionCommon::read_tls` by symbol; if
   symbols are stripped, walk the callers of your DNS/connect path.

## QUIC / HTTP/3 — the silent capture killer

Chromium-family clients negotiate HTTP/3 over **UDP**. A TCP-only proxy sees nothing
while the page still loads. This is the single most common reason "the capture is
empty but the app works".

- Browser/Electron: launch with `--disable-quic`, or set the client flag
  (`network.http.http3.enable=false` equivalent).
- Native with QUIC: block UDP/443 on the egress, or relay UDP through SOCKS5
  `UDP ASSOCIATE`; a plain HTTP proxy cannot do it.
- Confirm: in `curl` use `--http1.1`; in a browser check `Network` for `h3` in the
  protocol column, and for `alt-svc` headers in responses.

## Post-capture: turning bytes into a request you can send

1. **Deduplicate.** Group by `(method, path template)`; keep the newest observed
   header set, note which fields vary between calls.
2. **Diff two calls of the same endpoint.** The varying fields are the signature,
   nonce, timestamp, or state — nothing else.
3. **Find the producer.** Static: `bundle_scan.py` (`crypto_hook`, `prompt_assembly`)
   then read the module. Runtime: hook `crypto.subtle.sign/encrypt`, `CryptoJS.AES`,
   `SubtleCrypto`, and the wasm exports at document-start; log arguments and results.
4. **Reimplement in a standalone script**, replay with real values, and verify by
   comparing your replayed response to the captured one. A signature you cannot
   reproduce with the same input twice is not understood yet.
5. **Write it down** as a finding record with the algorithm, the inputs, and the
   replay evidence — that record is what makes the next session cheap.

## What this capture stack does *not* see

- **WebSocket frames are captured, but not decoded.** `proxy.py` records every frame as
  `{type: ws-frame, direction: c2s|s2c, opcode, payload}` plus a `ws-open` record;
  `cdp_capture.py` does the same from `Network.webSocketFrame*`. Binary frames land as
  `base64:`, protobuf/msgpack inside them is still yours to decode.
- **QUIC/HTTP3.** TCP proxies never see it; disable it on the client (see above).
- **TLS 1.3 payloads on pinned clients.** Only in-process hooks (Frida) see plaintext.
- **Non-HTTP transports.** gRPC over HTTP/2 is captured as opaque bytes; decode with
  `grpc` framing or use `inspect_pcap_capture` after a tcpdump/tshark pass.

## Capture defects you must not ship

- Body truncated without a `truncated` flag.
- Gzip/br bodies stored compressed and read as text.
- Only the response captured, so you cannot tell what the client actually sent.
- Secrets in cleartext in the capture file.
- A capture from a mutating addon presented as "what the client sent".
- One happy-path request captured and generalized into a protocol claim.
- A `100 Continue` / `103 Early Hints` interim response recorded as the final answer —
  `proxy.py` loops past 1xx and forwards them; verify the recorded `status` is 2xx.
- A request body silently truncated (check `req_body_truncated`, not just the length).
- Streaming verified by "the call returned" instead of by timestamped chunks arrowing
  in over time.