#!/usr/bin/env python3
"""Classify a target and print the exact route for reverse engineering it.

    python intake.py <path-or-url>
    python intake.py C:/targets/app.apk --json

Answers, in one call and in seconds: what is this, what can it tell us without
executing it, which analysis route applies, and which commands to run next.

Read-only and offline: hashes and header reads only. Nothing is decompiled here —
this decides *which* engine to pay for, so a wrong guess costs a second instead of
a session.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys

SKILL_SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REA_CLI = os.path.expandvars(r"%APPDATA%\npm\node_modules\rea-agents\scripts\rea.mjs")

MAGIC = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"PK\x03\x04": "zip",
    b"\x1f\x8b": "gzip",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"Rar!\x1a\x07": "rar",
    b"\xfd7zXZ": "xz",
    b"ustar": "tar",
    b"\xca\xfe\xba\xbe": "macho-fat",
    b"\xcf\xfa\xed\xfe": "macho64",
    b"\xce\xfa\xed\xfe": "macho32",
    b"\x00asm": "wasm",
    b"dex\n": "dex",
    b"ANDROID!": "android-boot",
    b"\x1f\x8b\x08": "gzip",
}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def first_bytes(path: str, n: int = 4096) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def detect(path: str) -> tuple[str, dict]:
    info: dict = {}
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return "url", {"url": path}

    if not os.path.exists(path):
        return "missing", {}

    if os.path.isdir(path):
        entries = sorted(os.listdir(path))
        info["entries"] = entries[:20]
        info["entry_count"] = len(entries)
        pkg = os.path.join(path, "package.json")
        if os.path.exists(pkg):
            try:
                meta = json.load(open(pkg, encoding="utf-8", errors="replace"))
                deps = {**meta.get("dependencies", {}), **meta.get("devDependencies", {})}
                info["package"] = meta.get("name")
                info["electron"] = "electron" in deps
                info["react"] = "react" in deps
            except Exception:  # noqa: BLE001
                pass
        # Electron first: a packaged app also ships .exe/.dll and would otherwise
        # be misrouted into the native lane. asar lives under resources/.
        asar = os.path.join(path, "resources", "app.asar")
        if os.path.exists(asar) or os.path.exists(os.path.join(path, "app.asar")) or info.get("electron"):
            info["asar"] = asar if os.path.exists(asar) else os.path.join(path, "app.asar")
            return "app-dir-electron", info
        if any(e.lower().endswith((".exe", ".dll")) for e in entries):
            return "app-dir-native", info
        return "dir", info

    size = os.path.getsize(path)
    info.update(size=size, ext=os.path.splitext(path)[1].lower())
    head = first_bytes(path, 8192)

    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            info["magic"] = magic.hex()
            if kind == "pe":
                if len(head) >= 0x40:
                    off = struct.unpack_from("<I", head, 0x3C)[0]
                    if off + 6 <= len(head) and head[off:off + 4] == b"PE\0\0":
                        info["machine"] = hex(struct.unpack_from("<H", head, off + 4)[0])
                        info["pe_offset"] = hex(off)
                info["dotnet"] = b"BSJB" in first_bytes(path, 1 << 20)
            if kind == "elf":
                info["elf_class"] = "64" if head[4] == 2 else "32"
                info["elf_le"] = head[5] == 1
            if kind == "zip":
                try:
                    import zipfile
                    with zipfile.ZipFile(path) as z:
                        names = z.namelist()
                        info["entries"] = len(names)
                        info["has_manifest"] = "AndroidManifest.xml" in names
                        info["has_dex"] = any(n.endswith(".dex") for n in names)
                        info["has_payload_app"] = any(n.startswith("Payload/") for n in names)
                        info["asar"] = any(n.endswith(".asar") for n in names)
                        info["info_plist"] = any(n.endswith("Info.plist") for n in names)
                except Exception:  # noqa: BLE001
                    pass
            # the extension decides the container's real identity
            if info["ext"] in {".apk", ".xapk"} or (info.get("has_manifest") and info.get("has_dex")):
                return "apk", info
            if info["ext"] in {".ipa", ".app"} or (info.get("has_payload_app") and info.get("info_plist")):
                return "ipa", info
            if info["ext"] == ".asar":
                return "asar", info
            if info["ext"] in {".aab"}:
                return "apk", info
            return kind, info

    # text-ish checks
    lowered = head.lower()
    if info["ext"] in {".js", ".mjs", ".cjs"} or b"webpack" in lowered or b"sourcemappingurl" in lowered:
        info["minified"] = size > 500_000 or lowered.count(b"\n") < size / 200
        return "javascript", info
    if b"asar" in lowered and info["ext"] == ".asar":
        return "asar", info
    if info["ext"] in {".bin", ".img", ".fw"}:
        return "firmware", info
    return "unknown", info


ROUTES: dict[str, dict] = {
    "url": {
        "first": "static bundle, then live capture",
        "commands": [
            "python {S}/web_bundle.py {T} --out artifacts/web --with-maps",
            "python {S}/bundle_scan.py artifacts/web --out artifacts/sinks.json",
            "python {S}/cdp_capture.py --port 9222 --out artifacts/cdp.jsonl --reload",
        ],
        "rea": "analyze_web_bundle / export_web_scripts / inspect_web_page",
    },
    "apk": {
        "first": "package + manifest (jadx/apktool), then class → method",
        "commands": [
            'rea inspect-android-package "{T}"',
            'rea search-android-classes "{T}" "<substring>"',
            'rea inspect-android-class "{T}" "<fq.Class>"',
            'rea inspect-android-method "{T}" "<fq.Class>" "<method>"',
            'rea decode-android-resources "{T}"',
            'rea inspect-apk-signature "{T}"',
        ],
        "rea": "inspect_android_package → search_android_classes → inspect_android_method",
        "then": "native libs inside: extract_artifact, then the elf route; runtime: adb + frida",
    },
    "pe": {
        "first": "triage (capa/floss), then Ghidra pseudocode through REA",
        "commands": [
            'capa "{T}"', 'floss "{T}"',
            'rea inspect-pe-imports "{T}"', 'rea inspect-pe-resources "{T}"',
            'rea search "{T}" . --kind procedures --mode regex --provider ghidra --json',
            'rea decompile "{T}" <address> --provider ghidra',
        ],
        "rea": "open_binary(provider_id=ghidra) → list_procedures → procedure_pseudo_code",
    },
    "elf": {
        "first": "imports/exports, then Ghidra or rizin",
        "commands": [
            'rea inspect-binary-layout "{T}"', 'rea inspect-native-exports "{T}"',
            'rizin -qc "aa; afl" "{T}"',
            'rea decompile "{T}" <address> --provider ghidra',
        ],
    },
    "macho64": {}, "macho32": {}, "macho-fat": {
        "first": "slices, then Hopper or Ghidra",
        "commands": ['rea list-architectures "{T}"', 'rea inspect-macho "{T}"'],
    },
    "ipa": {
        "first": "inventory the bundle, then Mach-O slice per binary",
        "commands": [
            'rea inspect-artifact "{T}"', 'rea inspect-plist "{T}"',
            'rea list-architectures "{T}"', 'rea inspect-macho "{T}"',
        ],
        "rea": "inspect_artifact → inspect_plist → inspect_macho",
    },
    "zip": {
        "first": "inventory first; the members decide the route",
        "commands": ['rea inspect-artifact "{T}"', 'rea extract-artifact "{T}"'],
    },
    "javascript": {
        "first": "source maps and sink map before reading minified code",
        "commands": [
            "python {S}/bundle_scan.py <dir-of-this-file> --out artifacts/sinks.json",
            "grep -o 'sourceMappingURL=.*' \"{T}\" | tail -1",
        ],
    },
    "asar": {
        "first": "unpack, then treat as a JS app",
        "commands": ['npx asar extract "{T}" app-extracted',
                     "python {S}/bundle_scan.py app-extracted --out artifacts/sinks.json"],
        "rea": "analyze_javascript_application",
    },
    "app-dir-electron": {
        "first": "ASAR + bundle scan + native modules; the shell exe is not the app",
        "commands": ['npx asar extract "{asar}" app-extracted',
                     "python {S}/bundle_scan.py app-extracted --out artifacts/sinks.json",
                     "python {S}/triage.py --dir \"{T}\" --out artifacts/triage-native.json",
                     "python {S}/proxy.py --port 8080 --out artifacts/flows.jsonl"],
        "then": "whole-shell triage only on request: triage.py <shell.exe> --include-shell (slow, generic)",
    },
    "app-dir-native": {
        "first": "identify the runtime, then native route",
        "commands": ['rea inspect-desktop-application "{T}"',
                     'rea inspect-electron-fuses "{T}"',
                     "python {S}/proxy.py --port 8080 --out artifacts/flows.jsonl"],
    },
    "dir": {
        "first": "inventory; then classify the largest artifacts inside",
        "commands": ["python {S}/bundle_scan.py \"{T}\" --out artifacts/sinks.json"],
    },
    "firmware": {
        "first": "carve regions, then extract",
        "commands": ['rea inspect-firmware-regions "{T}"', 'rea extract-firmware "{T}" <outdir>'],
    },
    "wasm": {"first": "decompile to WAT", "commands": ["wasm2wat \"{T}\" -o out.wat"],
             "rea": "inspect_artifact"},
    "dex": {"first": "treat as part of an APK", "commands": ['rea inspect-android-package "<apk>"']},
    "unknown": {"first": "entropy + strings, then guess from the strings",
                "commands": ['rea inspect-byte-entropy "{T}"', 'capa "{T}"']},
    "missing": {"first": "path does not exist", "commands": []},
}


def plan(kind: str, path: str, facts: dict | None = None) -> dict:
    route = ROUTES.get(kind, ROUTES["unknown"])
    asar = (facts or {}).get("asar") or os.path.join(path, "resources", "app.asar")
    cmds = [c.format(S=SKILL_SCRIPTS, T=path, asar=asar) for c in route.get("commands", [])]
    return {"kind": kind, "route": route.get("first"), "commands": cmds,
            "rea_tools": route.get("rea"), "then": route.get("then")}


def hints(kind: str, info: dict) -> list[str]:
    out = []
    if kind == "zip":
        if info.get("asar"):
            out.append("contains .asar → Electron app")
    if kind == "pe" and info.get("dotnet"):
        out.append(".NET assembly (BSJB present) → managed route: inspect_managed_artifact, not Ghidra first")
    if kind == "javascript" and info.get("minified"):
        out.append("minified: find the source map first, read code only after that fails")
    if kind == "url":
        out.append("if the page is behind a challenge, escalate: web_bundle → cdp_capture → proxy+frida")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--diff", default=None,
                    help="second binary/version: print the ghidriff command and exit")
    a = ap.parse_args()

    if a.diff:
        out = f"artifacts/diff-{os.path.basename(a.target)}-{os.path.basename(a.diff)}"
        print(f"python -m ghidriff \"{a.target}\" \"{a.diff}\" -o \"{out}\"")
        print("# then read the .ghidriff.md summary: added / deleted / modified functions first")
        return 0

    kind, info = detect(a.target)
    if kind not in ("url", "missing"):
        try:
            info["sha256"] = sha256(a.target) if os.path.isfile(a.target) else None
        except OSError as exc:
            info["sha256"] = f"error:{exc}"
    result = {"target": a.target, "classification": kind, "facts": info,
              **plan(kind, a.target, info), "hints": hints(kind, info)}

    if a.json:
        print(json.dumps(result, indent=1))
        return 0

    print(f"target:  {a.target}")
    print(f"class:   {kind}")
    for k in ("size", "sha256", "ext", "machine", "dotnet", "elf_class", "entries",
              "has_manifest", "has_dex", "asar", "electron", "package", "minified"):
        if info.get(k) not in (None, False, ""):
            print(f"  {k}: {info[k]}")
    print(f"\nroute:   {result['route']}")
    if result["commands"]:
        print("next:")
        for c in result["commands"]:
            print(f"  {c}")
    if result["rea_tools"]:
        print(f"rea:     {result['rea_tools']}")
    if result["then"]:
        print(f"then:    {result['then']}")
    for h in result["hints"]:
        print(f"note:    {h}")
    print(f"\nskill:   {SKILL_SCRIPTS}\nrea cli: {REA_CLI}")
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
