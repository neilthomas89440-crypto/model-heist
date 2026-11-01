#!/usr/bin/env python3
"""One-shot triage: facts, strings, imports, capabilities, packed-ness, YARA.

    python triage.py <binary> [--json] [--out triage.json]
                     [--rules C:\\tools\\yara-rules] [--timeout 300]

The point is to spend the FIRST minute well: every public agentic-RE pipeline
(Blazytko, REcon 2026, every malware course) starts with the same routine —
hashes, strings, imports, capa, YARA — and only then opens a decompiler. Doing it
by hand costs five shell calls and twenty minutes of scrolling; this returns one
artifact that says what the binary *is* and where to look next.

Design rules:
  * fail soft — a missing tool marks its step skipped with the reason, never aborts
  * bounded — every subprocess has a timeout, every list a cap
  * evidence — every claim carries the tool that produced it
  * no execution — strings/imports/YARA are static; capa and floss run on the file
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time

MAGIC = {
    b"MZ": "pe", b"\x7fELF": "elf", b"\xfe\xed\xfa\xce": "macho32",
    b"\xfe\xed\xfa\xcf": "macho64", b"\xca\xfe\xba\xbe": "macho-fat",
    b"PK\x03\x04": "zip", b"\x1f\x8b": "gzip", b"dex\n": "dex", b"\x00asm": "wasm",
}
INTERESTING = [
    ("url", re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,120}")),
    ("host", re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|io|so|ai|app|dev|cloud|ru|cn)\b", re.I)),
    ("model_id", re.compile(r"\b(?:gpt|claude|gemini|grok|deepseek|qwen|glm|kimi|llama|mistral)[-.][a-z0-9.-]{1,30}", re.I)),
    ("secretish", re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|tvly-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b")),
    ("crypto", re.compile(r"\b(?:AES|RSA|ChaCha20|HMAC|SHA-?256|Ed25519|X25519|argon2|pbkdf2)\b", re.I)),
    ("auth", re.compile(r"\b(?:Bearer|authorization|x-api-key|access_token|refresh_token|jwt|oauth)\b", re.I)),
    ("path_hint", re.compile(r"[A-Za-z]:\\\\?[A-Za-z0-9 _\-.\\\\]{4,80}")),
]


def sh(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except Exception as exc:  # noqa: BLE001
        return 1, "", f"{type(exc).__name__}: {exc}"


def facts(path: str) -> dict:
    size = os.path.getsize(path)
    h = hashlib.sha256()
    head = b""
    with open(path, "rb") as fh:
        first = fh.read(1 << 20)
        head = first[:16]
        h.update(first)
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    kind = next((v for k, v in MAGIC.items() if head.startswith(k)), "unknown")
    return {"path": os.path.abspath(path), "size": size, "sha256": h.hexdigest(), "kind": kind}


def entropy(path: str, block: int = 1 << 16) -> dict:
    """Whole-file entropy plus the highest block, which is what packing looks like."""
    counts = [0] * 256
    total = 0
    peak = 0.0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(block)
            if not chunk:
                break
            local = [0] * 256
            for b in chunk:
                local[b] += 1
            total += len(chunk)
            for i, c in enumerate(local):
                counts[i] += c
            e = _entropy(local, len(chunk))
            peak = max(peak, e)
    whole = _entropy(counts, total) if total else 0.0
    return {"whole": round(whole, 3), "peak_block": round(peak, 3)}


def _entropy(counts, n: int) -> float:
    if n <= 0:
        return 0.0
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def strings(blob: bytes, min_len: int = 6, cap: int = 4000) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
                if len(out) >= cap:
                    return out
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    # utf-16le
    try:
        wide = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", blob)
        for w in wide[:1000]:
            out.append(w.decode("utf-16le", "replace"))
    except Exception:  # noqa: BLE001
        pass
    return out


def interesting(strings_list: list[str]) -> dict:
    found: dict[str, list[str]] = {}
    for s in strings_list:
        for label, rx in INTERESTING:
            if rx.search(s):
                bucket = found.setdefault(label, [])
                if len(bucket) < 25 and s not in bucket:
                    bucket.append(s[:160])
    return found


def imports_pe(path: str) -> dict:
    try:
        import pefile  # type: ignore
    except ImportError:
        rc, out, err = sh(["python", "-c", "import pefile"], 20)
        return {"skipped": "pefile not installed (pip install pefile)"}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
        libs: dict[str, list[str]] = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            names = [imp.name.decode() for imp in entry.imports if imp.name][:60]
            libs[entry.dll.decode()] = names
        for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or []:
            names = [imp.name.decode() for imp in entry.imports if imp.name][:40]
            libs["(delay) " + entry.dll.decode()] = names
        return {"libs": libs, "machine": hex(pe.FILE_HEADER.Machine),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000)}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def capa_exe() -> str | None:
    """Prefer the release build: the pip wheel ships neither rules nor signatures."""
    for cand in (r"C:\tools\capa\capa.exe",):
        if os.path.exists(cand):
            return cand
    return shutil.which("capa")


def run_capa(path: str, timeout: int, rules_dir: str | None = None) -> dict:
    exe = capa_exe()
    if not exe:
        return {"skipped": "capa not installed"}
    cmd = [exe, "-j"]
    if rules_dir and os.path.isdir(rules_dir):
        cmd += ["-r", rules_dir]
    cmd.append(path)
    rc, out, err = sh(cmd, timeout)
    if rc != 0:
        return {"skipped": f"capa rc={rc}: {(err or out)[:160]}"}
    try:
        d = json.loads(out)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"json: {exc}"}
    rules = d.get("rules") or {}
    def _tags(key: str) -> list[str]:
        vals = []
        for body in rules.values():
            meta = body.get("meta") or {}
            for t in (meta.get(key) or meta.get("att&ck" if key == "attack" else key) or []):
                if isinstance(t, dict):
                    vals.append(str(t.get("technique") or t.get("objective")
                                     or t.get("id") or "?")[:48])
                else:
                    vals.append(str(t)[:48])
        return sorted(set(vals))

    attacks = _tags("attack")
    mbc = _tags("mbc")
    return {"count": len(rules), "attack": attacks[:20], "mbc": mbc[:10],
            "sample": sorted(rules)[:25]}


def run_floss(path: str, timeout: int) -> dict:
    if not shutil.which("floss"):
        return {"skipped": "floss not installed"}
    rc, out, err = sh(["floss", "-j", path], timeout)
    if rc != 0:
        return {"skipped": f"floss rc={rc}: {(err or out)[:160]}"}
    try:
        d = json.loads(out)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"json: {exc}"}
    dec = d.get("strings") or {}
    out_d: dict[str, int] = {}
    samples: list[str] = []
    for bucket in ("decoded_strings", "stack_strings", "tight_strings"):
        items = dec.get(bucket) or []
        out_d[bucket] = len(items)
        for it in items[:10]:
            s = it.get("string") if isinstance(it, dict) else str(it)
            if s:
                samples.append(s[:120])
    return {"counts": out_d, "sample": samples[:20]}


def run_yara(path: str, rules_dir: str | None, timeout: int) -> dict:
    if not rules_dir or not os.path.isdir(rules_dir):
        return {"skipped": "no rules dir (--rules)"}
    try:
        import yara  # type: ignore
    except ImportError:
        return {"skipped": "yara-python not installed"}
    files = {}
    for root, _dirs, names in os.walk(rules_dir):
        for n in names:
            if n.endswith((".yar", ".yara")):
                p = os.path.join(root, n)
                key = os.path.relpath(p, rules_dir).replace("\\", "/")
                files[key] = p
                if len(files) >= 3000:
                    break
    if not files:
        return {"skipped": "no .yar files found"}
    try:
        compiled = yara.compile(filepaths=files)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"compile failed: {type(exc).__name__}: {exc}"[:300]}
    try:
        matches = compiled.match(path, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"scan failed: {exc}"[:200]}
    return {"rules_loaded": len(files),
            "matches": [{"rule": m.rule, "tags": list(m.tags), "namespace": m.namespace}
                        for m in matches][:60]}


def verdict(f: dict, ent: dict, pe: dict, caps: dict, yara_res: dict, inter: dict) -> list[str]:
    out: list[str] = []
    kind = f["kind"]
    if kind == "pe" and pe.get("dll"):
        out.append("PE DLL, not an executable")
    if kind == "pe" and "mscoree.dll" in (pe.get("libs") or {}):
        out.append(".NET assembly (mscoree) → managed route first, not Ghidra")
    elif "BSJB" in "".join((pe.get("libs") or {}).keys()):
        out.append("possible .NET metadata (BSJB) — confirm with inspect_managed_artifact")
    if ent["whole"] > 7.2 or ent["peak_block"] > 7.6:
        out.append(f"high entropy (whole {ent['whole']}, peak {ent['peak_block']}) → "
                   "packed or compressed; unpack before trusting pseudocode")
    if caps.get("skipped") is None and caps.get("count"):
        out.append(f"capa: {caps['count']} rules matched"
                   + (f", ATT&CK {len(caps.get('attack') or [])}" if caps.get("attack") else ""))
    if yara_res.get("matches"):
        out.append(f"YARA: {len(yara_res['matches'])} rule(s) matched — read them before disassembly")
    for key in ("secretish", "model_id", "url", "auth"):
        if inter.get(key):
            out.append(f"interesting {key}: {len(inter[key])} hit(s)")
    if not out:
        out.append("nothing anomalous in the static pass; go to imports/strings by hand")
    return out


NATIVE_EXT = (".node", ".dll", ".exe", ".so", ".dylib")
SHELL_NOISE = re.compile(
    r"^(?:electron|libegl|libglesv2|ffmpeg|vk_swiftshader|d3dcompiler|dxcompiler|dxil|"
    r"icudtl|snapshot_blob|v8_context_snapshot|chrome_|resources|app)\.", re.I)


def discover_native(app_dir: str, limit: int, max_mb: int, include_shell: bool) -> list[dict]:
    """Native modules worth triaging inside an Electron install.

    The shell executable is a Chromium build: hundreds of MB, no application logic, and
    capa on it costs minutes for nothing. What carries the app's native behaviour is
    `resources/**/*.node`, `app.asar.unpacked/**` and any DLL/EXE the app ships inside
    `resources/`.
    """
    root = os.path.join(app_dir, "resources")
    if not os.path.isdir(root):
        root = app_dir
    found: list[dict] = []
    cap = max_mb * 1024 * 1024
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"locales", "Cache", "GPUCache"}]
        for name in filenames:
            low = name.lower()
            if not low.endswith(NATIVE_EXT):
                continue
            if not include_shell and SHELL_NOISE.match(low):
                continue
            full = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > cap:
                continue
            found.append({"path": full, "size": size, "name": name})
    def rank(rec: dict) -> tuple:
        """App-owned addons first; bundled third-party binaries (ripgrep, onnxruntime,
        a browser) are interesting but they are not the app's own logic."""
        p = rec["path"].lower().replace("\\", "/")
        is_node = p.endswith(".node")
        app_owned = ("app.asar.unpacked" in p) or ("/@orca/" in p) or ("@granola" in p)
        return (0 if is_node else 1, 0 if app_owned else 1, -rec["size"])

    found.sort(key=rank)
    return found[:limit]


def analyze_file(path: str, *, rules: str | None, timeout: int, max_strings: int,
                 skip_heavy: bool = False) -> dict:
    t0 = time.time()
    steps: dict[str, dict] = {}
    f = facts(path)
    steps["facts"] = f

    ent = entropy(path)
    steps["entropy"] = ent

    blob = open(path, "rb").read(24 << 20)
    strs = strings(blob, cap=max_strings)
    inter = interesting(strs)
    steps["strings"] = {"count": len(strs), "sample": strs[:40], "interesting": inter}

    if f["kind"] == "pe":
        steps["imports"] = imports_pe(path)

    if skip_heavy:
        steps["capa"] = {"skipped": "heavy step skipped for this file size"}
        steps["floss"] = {"skipped": "heavy step skipped for this file size"}
    else:
        steps["capa"] = run_capa(path, timeout, None)
        steps["floss"] = run_floss(path, timeout)
    steps["yara"] = run_yara(path, rules, timeout)

    summary = verdict(f, ent, steps.get("imports") or {}, steps["capa"], steps["yara"], inter)
    return {"target": f, "verdict": summary, "steps": steps,
            "elapsed_s": round(time.time() - t0, 1)}


def print_report(rep: dict) -> None:
    f = rep["target"]
    ent = rep["steps"]["entropy"]
    print(f"\n{f['path']}\n  {f['kind']}  {f['size']} bytes  sha256 {f['sha256'][:32]}…")
    print(f"  entropy whole {ent['whole']}  peak block {ent['peak_block']}")
    print("verdict:")
    for line in rep["verdict"]:
        print("  -", line)
    imp = rep["steps"].get("imports") or {}
    if imp.get("libs"):
        print(f"imports: {len(imp['libs'])} libs — {', '.join(list(imp['libs'])[:8])}")
    caps = rep["steps"]["capa"]
    if caps.get("count"):
        print(f"capa: {caps['count']} rules; ATT&CK: {', '.join((caps.get('attack') or [])[:6])}")
    elif caps.get("skipped"):
        print(f"capa: {caps['skipped']}")
    yr = rep["steps"]["yara"]
    if yr.get("matches"):
        print("yara: " + ", ".join(m["rule"] for m in yr["matches"][:10]))
    elif yr.get("skipped"):
        print(f"yara: {yr['skipped']}")
    fl = rep["steps"]["floss"]
    if fl.get("counts"):
        print("floss: " + ", ".join(f"{k}={v}" for k, v in fl["counts"].items()))
    print(f"elapsed {rep['elapsed_s']}s")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="binary to analyze")
    ap.add_argument("--dir", default=None,
                    help="Electron/app directory: triage its native modules, not the shell")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--rules", default=os.environ.get("YARA_RULES_DIR",
                                                      r"C:\tools\yara-rules"))
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--max-strings", type=int, default=4000)
    ap.add_argument("--capa-rules", default=None,
                    help="override capa's embedded rules with a directory")
    ap.add_argument("--limit", type=int, default=5, help="modules to triage in --dir mode")
    ap.add_argument("--max-mb", type=int, default=64, help="skip modules bigger than this")
    ap.add_argument("--include-shell", action="store_true",
                    help="also triage the Electron/Chromium shell binaries (slow)")
    ap.add_argument("--heavy-mb", type=int, default=16,
                    help="above this size skip capa/floss for that module")
    a = ap.parse_args()

    if a.dir:
        mods = discover_native(a.dir, a.limit, a.max_mb, a.include_shell)
        if not mods:
            print(f"no native modules under {a.dir}", file=sys.stderr)
            return 3
        print(f"{len(mods)} native module(s) in {a.dir} (app-owned addons first, then size):")
        for m in mods:
            print(f"  {m['size']:>10}  {os.path.relpath(m['path'], a.dir)}")
        reports = []
        for m in mods:
            print(f"\n=== {m['name']} ===")
            rep = analyze_file(m["path"], rules=a.rules, timeout=a.timeout,
                               max_strings=a.max_strings,
                               skip_heavy=m["size"] > a.heavy_mb * 1024 * 1024)
            reports.append(rep)
            print_report(rep)
        out = {"dir": os.path.abspath(a.dir), "modules": reports,
               "note": "Electron shell intentionally excluded unless --include-shell"}
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8") as fh:
                json.dump(out, fh, indent=1)
            print(f"\nwrote {os.path.abspath(a.out)}")
        if a.json:
            print(json.dumps(out, indent=1))
        return 0

    if not a.target:
        print("pass a binary, or --dir <app dir>", file=sys.stderr)
        return 2
    if not os.path.isfile(a.target):
        print(f"not a file: {a.target}", file=sys.stderr)
        return 2

    rep = analyze_file(a.target, rules=a.rules, timeout=a.timeout,
                       max_strings=a.max_strings)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1)
    if a.json:
        print(json.dumps(rep, indent=1))
        return 0
    print_report(rep)
    if a.out:
        print(f"wrote {os.path.abspath(a.out)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        import os as _os
        _os._exit(0)