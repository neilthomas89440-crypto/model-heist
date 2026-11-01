# Routing: artifact → tools → extraction

One rule: **identify the artifact class before touching it.** Wrong router wastes a
session; guessed extraction wastes more. `python scripts/intake.py <target>` does that
classification and prints the command list; the tables below are the detail behind it.

## First minute, always: triage

```bash
python $S/triage.py <binary> --out artifacts/triage.json
```

Hashes, entropy (whole + peak block), strings + interesting-string buckets (urls, model
ids, secret-shaped tokens, crypto/auth keywords, Windows paths), PE imports, capa
capabilities + ATT&CK, floss decoded strings, YARA over `C:\\tools\\yara-rules`.
One artifact answers "what is this and where do I look", so the decompiler is spent on a
function instead of on the file.

## Two versions of the same thing

```bash
python -m ghidriff old.exe new.exe -o artifacts/diff     # Ghidra-based, version tracking
```

**Electron apps: triage the modules, never the shell.** The 240 MB `*.exe` is a Chromium
build with no application logic — capa on it burns minutes and returns generic results.

```bash
python $S/triage.py --dir "C:\\path\\to\\App" --limit 5 --out artifacts/triage-native.json
```

It walks `resources/**` for `.node` / `.dll` / `.exe`, **ranks the app's own addons first**
(`.node`, `app.asar.unpacked`, `@app/*`) and bundled third-party binaries last (ripgrep,
onnxruntime, an embedded browser are interesting but they are not the app's logic),
skips Electron/Chromium noise
(`electron*`, `libEGL`, `ffmpeg`, `vk_swiftshader`, `d3dcompiler`, `dx*`, `icudtl`,
`snapshot_blob`, …), sorts largest-first, and skips capa/floss above `--heavy-mb` (16 MB
default). `--include-shell` exists for the rare case where the shell itself matters.
Measured: 1.5 s for a 65 KB PE, 77 s for a 165 KB N-API module with floss+capa.

Run it **before** reading code: the diff names the added/modified functions, and the
change between releases is usually the interesting part (a patched check, a new endpoint,
a rotated constant). Inventory both sides first, then decompile only the delta.

## Native binary (PE, ELF, Mach-O)

```text
open_binary(path)                     # bind the target
binary_overview                       # segments, counts, entry
search_strings / list_strings         # config keys, hosts, model ids
search_procedures / list_procedures
analyze_function(symbol|address)      # pseudocode + calls + refs + strings
procedure_pseudo_code, procedure_callees, procedure_callers
xrefs(address)                        # who reads this constant
trace_call_path(start, goal)          # how config reaches the request builder
batch_decompile([...])                # bulk, once, when you need many functions
close_binary                          # when the investigation ends
```

Sub-cases that change the plan:

| Case | Do this |
|---|---|
| Managed/.NET PE | `inspect_managed_artifact` → `inspect_managed_members`; IL is readable, don't burn time in Ghidra |
| .NET NativeAOT | native route, but first try `inspect_managed_artifact` for residual metadata |
| Mach-O / IPA | `inspect_macho`, `list_architectures`, `inspect_signature`, then native route per slice |
| Stripped ELF, damaged section table | `inspect_binary_layout` (program headers); Kuna loads these anyway |
| Packed / UPX | unpack before analysis; pseudocode of a packer stub is noise |
| Prefer Hex-Rays | `rea decompile <path> <addr> --provider ida` — needs `REA_IDA_MCP_CONFIG`
  pointing at a registration that runs `idalib-mcp --stdio --max-workers 1`
  with `mode: headless`. Works without a GUI; 5 s per function on a small PE |
| Need speed on a big image | `kuna decompile <path> <addr> --json` (set `KUNA_ROOT` to the
  repo root so it finds its `.sla` specs; build with `make binaries && make specs`).
  Measured on the same PE function: **Kuna 0.1 s**, IDA 5.2 s, Ghidra ~40 s.
  REA's kuna provider is Linux/macOS + ELF/Mach-O only — on Windows/PE call the CLI directly |
| Swift | `demangle_swift`, `analyze_swift_types` before reading names |
| PE resources / icons / manifests | `inspect_pe_resources`, `inspect_plist` |

For a bundled JS runtime inside a native executable (Electron, Bun `--compile`, `pkg`,
Deno): the native layer is a loader. Find the archive first (`---- Bun! ----`, `PK\x03\x04`,
`.bun` section, `asar` magic), extract, then switch to the JavaScript route. Do not
reverse the runtime.

## JavaScript: web, ASAR, extracted tree

```text
analyze_web_bundle(url|path)          # chunk graph, routes, endpoints, vendor prints
export_web_scripts(capture.json)      # digest-verified script export
analyze_javascript_application(tree)  # ASAR or extracted app; graph + semantics
trace_feature(seed, graph)            # literal → strings → procedures → xrefs
trace_javascript_semantics(...)       # data flow, call/return, closures
compare_application_versions(a,b)     # what the update changed
```

Then `bundle_scan.py` over the exported tree for the sink map. Source maps, when
shipped, are the cheapest win of the whole skill — check `//# sourceMappingURL` and
`.map` files before reading minified code.

## Android

```text
inspect_android_package(apk)          # manifest, permissions, SDK, counts
decode_android_resources(apk)         # readable manifest + resource table
search_android_classes(query)         # class inventory / substring search
inspect_android_class(class)          # methods, fields, signatures
inspect_android_method(class, method) # decompiled body (smali fallback)
trace_android_references(class|method)# who calls the token mint
```

Native libs inside the APK: extract, then the native route. `strings` on
`lib/*/*.so` finds endpoint hosts faster than decompilation.

### Android lane, verified end to end (no device required)

```
intake.py app.apk                          -> class=apk, sha256, manifest/dex presence
rea inspect-android-package app.apk        -> package, versionCode, minSdk/targetSdk, permissions
rea search-android-classes app.apk <sub>   -> 12k-class index, substring match (case-sensitive)
rea inspect-android-class app.apk <Fq.Cls> -> methods, fields, inner classes
rea inspect-android-method app.apk <Cls> <m>-> source, representation, fell_back, markers
rea decode-android-resources app.apk       -> readable AndroidManifest.xml (apktool)
rea inspect-apk-signature app.apk          -> v1/v2/v3 schemes, signer certs
```

Runtime half — needs a device or emulator, and is the only part that cannot be
rehearsed offline:

```bash
adb devices                                  # REA reports client version + empty list cleanly
adb reverse tcp:8080 tcp:8080                # device -> your proxy.py
adb shell settings put global http_proxy 127.0.0.1:8080
frida -U -f <pkg> -l hooks/ssl.js --no-pause # spawn with hooks; targetSdk>=24 ignores user CAs
```

No device: the static half above plus `extract_artifact` (native `.so` → the ELF/Mach-O
route) still answers "where does the token come from".

## Apple app bundle

```text
inspect_artifact(.app|.ipa|.dmg)      # inventory + integrity graph
inspect_plist                          # Info.plist, entitlements
inspect_keyed_archive(path)           # NSKeyedArchiver stores (auth blobs live here)
decode_interface_builder                # storyboards/nibs → UI → handler names
inspect_asset_catalog
trace_dylib_resolution                  # which lib provides which symbol
```

Keychain items are not in the bundle. They are in the user's keychain — a runtime
problem, not a static one.

## Firmware and opaque archives

```text
inspect_firmware_regions(file)         # signatures: squashfs, ubifs, gzip, tarball
extract_firmware(file, outdir)         # verified children + digests
extract_artifact(active)               # zip/apk/ipa/msix/dmg members
```

## Runtime targets

```text
list_browser_targets(origin)           # pages on a loopback CDP endpoint
inspect_web_page(...)                  # passive: DOM, storage, listeners, scripts
observe_web_session(...)               # capture while the user operates it
capture_browser_scenario(...)          # scripted click/wait when passive cannot
inspect_web_network_capture(har|mitm)  # analyze a capture you already made
list_electron_targets / observe_javascript_runtime
```

Native runtime: `observe_native_calls` (LLDB), `observe_native_ui`, `capture_process_scenario`
(PTY). Memory-level: a Cheat Engine bridge or a small `ReadProcessMemory` scanner.

## Speed rules (adopted from the lean-RE school)

1. **One batched recon call, not ten.** Group independent probes into one shell call with
   `echo '--- name'` markers, cap every output with `head`.
2. **`rg -uu` or you will miss code.** Bundlers hide modules in dot-directories
   (`.webpack/`, `.vite/`); default ripgrep skips hidden and gitignored paths.
3. **Never `cat` a minified bundle.** Slice around the needle:
   `rg -o '.{0,200}NEEDLE.{0,200}' file | head`.
4. **Dump a disassembly once to a file, then grep the file** — do not re-run the tool to
   look again.
5. **Inventory before code.** Exports/imports/strings/dependency lists answer "what does it
   do" for most binaries without a decompiler step.
6. **Turns cost more than bytes.** Two to four calls to an answer beats twenty thorough ones.
7. **Label claims**: `seen` (file:offset, symbol, response) vs `inferred`. A fact you did not
   find is `unknown`, not absent.

## Evidence discipline per tool

- Cite the **Evidence id** the tool returns, plus address or file:line.
- A tool summary is not evidence for a raw payload; quote the payload.
- `detail: "summary"` first for anything large, then `inspect_analysis_view` on the
  retained id. Never re-run an identical analysis to "look again".
- When the client truncates a result, that preview is not canonical — page it or
  export the bundle.

## When the toolset is absent

Fall back in this order and record which method produced each fact:

1. extraction by format (unzip, asar, `--compile` trailer parse),
2. `strings` + `grep` for hosts, routes, model ids, `client_id`, `api_key`,
3. a local intercepting proxy ([traffic](traffic.md)),
4. CDP against the running client,
5. Frida for the process that ignores all of the above.

Never present a fallback fact as if REA produced it.