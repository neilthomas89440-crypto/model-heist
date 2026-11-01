# Corpus: mechanisms proven in the wild

Field notes from public reverse-engineering projects, kept because each one is a
**transferable mechanism**, not because the product is interesting. Study them the way
you study a cracked crackme: the technique outlives the target.

Status marking used below:
`code` — read in the cloned repository, behaviour verified in the source.
`claim` — asserted by the project's write-up and not verified here. Treat as a
hypothesis generator only.

## 1. CLI device-flow mint that bypasses the web captcha — `code`

`tokenharbor-2api/auth_device.py`. The web login is protected by Turnstile; the
official *CLI* ships a device-authorization endpoint that is not.

```text
POST /api/cli/auth/init      {"client_label":"halyard","device":{...}}
  -> {session_id, auth_url}
user opens auth_url, clicks approve
GET  /api/cli/auth/status?session=<id>   (poll every 2s)
  -> {"status":"approved","key":"..."}
```

Transfers to any product with a first-party CLI: the CLI's endpoints are usually
exempted from bot protection because the CLI cannot solve a challenge. Probe list for
your target: `/api/cli/auth/init`, `/api/device/code`, `/oauth/device`, `/api/v1/cli/*`.
Detect it statically: `bundle_scan.py` class `token_mint`, plus `grep -i "device"` in
the CLI's own bundle.

## 2. Free-tier route expressed as a model id, remapped in the gateway — `code`

`tokenharbor-2api/server.py`. The catalog carries a dedicated route
(`deepseek-v4.1-flash:free`) that bills against a free tier rather than the balance;
the gateway rewrites any incoming model name onto it and cycles a key pool with
`itertools.cycle`.

Transfer: always ask the *catalog* what exists before assuming the UI's model list is
complete — `/v1/models`, `/api/models`, and the client's own model table. Then test
`<model>:free`, `-free`, `-mini`, `:beta` variants. The suffix is meaningless unless a
probe shows the same weights behind it; run `heist.py triage` on each variant.

## 3. Trial/credit farm with disposable mail — `code`

`flonno-2api/core/minter.py`. Clerk-based signup, IMAP OTP fetch, optional captcha
solver, then a claim call that credits the new account. Transferable part is the
*shape*: signup → verify → claim endpoint, each an independent HTTP step that does not
need a browser if the app exposes JSON routes.

This is the mechanism behind `skill://autoreg-pools`. In this skill it is a **reject**
item: breadth replaces one limit with N accounts, and says nothing about whether the
product can be broken.

## 4. At-rest encrypted credential + key recovered from live process memory — `code`

`workbuddy2api-hub/wb_atrest.py`. The desktop client stores tokens as
`{"$wbEncrypted":1,"envelope":"base64(JSON{suite,keyId,nonce,authTag,ciphertext})"}`,
AES-256-GCM, with the content key derived from a build-time secret.

Recovery, in tiers, cheap to expensive:

1. find the key material as a literal token in the process (a 44-char canonical base64
   string is highly distinctive);
2. hash candidate windows and compare against the `keyId` recorded in the keyblob;
3. only then scan byte-by-byte;
4. verify every candidate by **actually decrypting** the envelope — a hash match alone
   is a guess, a successful unwrap is proof.

Windows mechanics: `OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)` →
`VirtualQueryEx` for readable `MEM_PRIVATE` regions → `ReadProcessMemory`. Read-only,
no writes into the target. On other platforms the same file requires the user to paste
the key once.

Transfer: any desktop client with an "encrypted" local store is either (a) encrypted
with a key it also stores, (b) derived from a machine/user secret you can query, or
(c) fetched at runtime and held in memory. Case (c) is this module. Do not start with
a full byte scan; start with the structure (key id, magic, framing).

## 5. Host-level OS crypto unwrap — `code`

`Buddy2api/credential_crypto.py`. Two envelopes side by side: a local Fernet key file
with `0600`, and a DPAPI-prefixed blob that is unwrapped with `CryptUnprotectData`
under the current user. Because the gateway runs on the user's own machine, the OS
does the decryption and no secret needs to be extracted at all.

Transfer: before writing a memory scanner, check whether the client uses DPAPI,
Keychain, libsecret, or `safeStorage` — if the attacker's process runs as the same
user, those APIs are free decryption oracles.

## 6. Browser session → local API, with OAuth config scraped from the client binary — `code`

`dario` (`src/cc-oauth-detect.ts`, `src/accounts.ts`). Instead of hardcoding the
provider's OAuth client id (which rotates), it scans the installed CLI binary at
runtime for the live `client_id`/authorize/token URLs, then runs that client's own
OAuth flow with a localhost callback, and stores per-account refreshers under
`~/.dario/accounts/`. Pool mode activates by directory content, and failover on 429
switches accounts mid-stream.

Transfer: **derive config from the artifact you are attacking** — client ids, scopes,
URLs, feature flags are all in there. A hardcoded constant from a blog post is stale
proof.

## 7. Protocol bridge (Anthropic ⇄ OpenAI ⇄ Gemini) with ReAct fallback — `code`

`UniClaudeProxy/app/converters/*`. Converts request/response shapes both ways, streams
in both directions, and falls back to wrapping tool calls in XML for models without
native function calling.

Transfer: this is the shape of every "2API" gateway. Build the converter once, test it
with a stub, and keep streaming conversion separate from non-streaming — they fail
differently and only streaming exposes framing bugs.

## 8. Extracting a JS application from a packaged runtime — `code`

`claude-code-reverse-engineering/scripts/0*.py`. A 215 MB executable built with
`bun build --compile`: PE sections `.text`/`.rdata`/`.bun`, and the `.bun` section is a
virtual filesystem ending in a `---- Bun! ----` trailer. The parser walks 36-byte module
descriptors and reconstructs the main 16.5 MB `cli.js`.

Transfer: packaged Node/Bun/Deno CLIs are archives. Look for the trailer/magic first
(`strings -n 8 | grep -i bun\|asar\|pkg\|ncc`), then parse descriptors rather than
carving strings. The recovered bundle is then ordinary JS for `bundle_scan.py`.

## 9. Interception as a product: embedded MITM + document-start hooks — `code`

`anything-analyzer/src/main/proxy/mitm-proxy-server.ts`,
`src/main/proxy/ca-manager.ts`, `src/preload/hook-script.ts`. An embedded proxy issues
per-host certs on demand, decodes `br`/`gzip`/`deflate`, caps bodies at 1 MB, and can
chain to a SOCKS upstream; a preload script wraps `fetch`, `XMLHttpRequest`,
`crypto.subtle` and `CryptoJS` at document-start and reports arguments, results and
stack traces.

Transfer: the hook must be installed **before** the page's own code, otherwise the app
captures your wrapper. In CDP that means `Page.addScriptToEvaluateOnNewDocument`, not
`Runtime.evaluate` after load.

## 10. Decompiler tuned for agents — `code`

`kuna` (Rust, `docs/cli.md`). CLI subcommands with `--json` documents, help that works
without a loaded binary, tolerant loading of damaged ELF section tables, and output
shaped for LLM consumption rather than screen reading.

Transfer: for bulk pseudocode prefer a JSON-emitting decompiler and page the results by
address; never paste a whole function list into context.

## 11. Challenge handling and fingerprinting at engine level — `claim` + `code`

`trawl` (HTTP-first, clearance reuse, Camoufox fallback, MCP surface) and
`clearcote-browser` / `ShardBrowser` (fingerprint coherence inside the C++ engine
rather than JS injection). The `code` part visible in the repos is the architecture:
attempt HTTP, reuse a verified clearance, escalate to a real browser only when the
challenge demands it.

Transfer: JS-level stealth is a dead end (`Function.prototype.toString` exposes it).
If a target blocks automation, the lever is the engine build, the TLS/JA fingerprint,
and the IP reputation — not a longer patch script. And QUIC/UDP is what TCP proxies
miss; see [traffic](traffic.md).

## 12. Client-side project encryption with a key hidden in the payload — `claim`

The CapCut/Jianying write-up: 12 fixed offsets carry 48 ASCII bytes, 32 of which are
the AES-256 key and 16 the GCM IV; the remainder is base64 ciphertext plus a 16-byte
tag. Whether or not the offsets hold for your build, the *pattern* is common: a key
smuggled into the artifact at a fixed position, so the format is recoverable by
locating high-entropy substrings and validating with a decrypt attempt.

## What generalizes

| Mechanism | Where it appears | First probe |
|---|---|---|
| CLI-only auth endpoint | any product with a first-party CLI | enumerate `/api/cli`, `/device` routes |
| Free route as a model-id suffix | vendors with trial/free tiers | `heist.py sweep` + suffix variants |
| Local encrypted store | desktop clients | find the envelope, then the key source (file / OS API / memory) |
| Config derived from the artifact | anything with an OAuth client id | scan the binary/bundle for client_id, scopes, URLs |
| Packaged JS runtime | Electron/Bun/Deno CLIs | trailer/magic hunt, then descriptor parse |
| Protocol bridge | every "2API" gateway | build converter, test streaming separately |
| Node/host-level crypto | anything running as your user | try the OS API before extracting secrets |

## What does not generalize

- Expiring free tiers and referral credits: a countdown, not a channel.
- Selenium-style JS stealth patches: detected by construction.
- Hardcoded constants from a write-up: rotated by the vendor, stale by the time you
  read it.
- A working exploit without a measured meter: you do not know what you got.