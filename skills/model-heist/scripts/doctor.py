#!/usr/bin/env python3
"""Report what reverse-engineering capability this machine actually has.

    python doctor.py            # human table + what you can/can't do
    python doctor.py --json     # machine-readable

Read-only: probes versions and paths, never installs or launches a disassembler.
Every missing item prints the exact command that fixes it.

Why this exists: a skill that assumes Ghidra, jadx, or a debugger is present
silently degrades into "read strings and hope". This tells you which phase of the
workflow is actually runnable before you plan a session around it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

REA_MJS = os.path.expandvars(
    r"%APPDATA%\npm\node_modules\rea-agents\scripts\rea.mjs")

# capability -> (check id, human label, what it unlocks)
CAPABILITIES: list[tuple[str, str, str]] = [
    ("capture", "traffic capture", "proxy.py / cdp_capture.py (stdlib only)"),
    ("static-py", "python static pass", "bundle_scan.py / web_bundle.py"),
    ("capa", "capability detection", "what a binary does, ATT&CK mapping"),
    ("floss", "obfuscated strings", "strings a plain `strings` misses"),
    ("ghidra", "Ghidra decompiler", "native pseudocode for PE/ELF/Mach-O via REA"),
    ("ida", "IDA Pro", "best-in-class pseudocode + debugger via IDA MCP"),
    ("rizin", "rizin / radare2", "CLI disassembly, scriptable"),
    ("jadx", "JADX", "APK/DEX decompilation via REA"),
    ("apktool", "apktool", "APK resources/manifest decode via REA"),
    ("frida", "Frida", "runtime hooks, TLS pinning defeat"),
    ("x64dbg", "x64dbg", "Windows debugging, unpacking"),
    ("binwalk", "binwalk", "firmware carving"),
    ("tshark", "tshark", "pcap analysis, TLS SNI inventory"),
    ("kuna", "Kuna decompiler", "agent-first pseudocode, REA_KUNA_COMMAND"),
    ("adb", "adb", "Android device capture"),
    ("dotnet", ".NET SDK", "managed assembly work, launcher shims"),
]


def run(cmd: list[str], timeout: int = 20) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or r.stderr or "").strip().splitlines()
        return r.returncode == 0, out[0][:120] if out else ""
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}"


TOOL_DIRS = [r"C:\tools", r"C:\tools\bin", os.path.expanduser(r"~\tools"),
             os.path.expanduser(r"~\.cargo\bin")]


def find_exe(names: list[str], extra: list[str] | None = None) -> str | None:
    """PATH first, then the conventional local tool dirs.

    PATH is not reliable from inside a long-lived agent process (an install made
    this session is invisible until restart), so probe known locations too.
    """
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    for cand in (extra or []):
        if os.path.exists(cand):
            return cand
    for root in TOOL_DIRS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath.count(os.sep) - root.count(os.sep) > 3:
                dirnames[:] = []
                continue
            for n in names:
                for f in filenames:
                    if f.lower() in {n.lower(), n.lower() + ".exe", n.lower() + ".bat", n.lower() + ".cmd"}:
                        return os.path.join(dirpath, f)
    return None


def check_py_module(name: str) -> tuple[bool, str]:
    try:
        mod = __import__(name)
        return True, getattr(mod, "__version__", "installed")
    except Exception:  # noqa: BLE001
        return False, ""


def ghidra_report() -> tuple[bool, str, dict]:
    d = os.environ.get("GHIDRA_INSTALL_DIR", "")
    info: dict = {"install_dir": d or None, "version": None, "java_home": os.environ.get("JAVA_HOME")}
    if not d:
        for guess in (r"C:\tools", r"C:\Program Files", os.path.expanduser("~")):
            if not os.path.isdir(guess):
                continue
            for entry in sorted(os.listdir(guess)):
                if entry.lower().startswith("ghidra_") and os.path.isdir(os.path.join(guess, entry)):
                    d = os.path.join(guess, entry)
                    info["install_dir"] = d
                    info["discovered_at"] = guess
                    break
            if info["install_dir"]:
                break
    if not d:
        return False, "", info
    props = os.path.join(d, "Ghidra", "application.properties")
    version = ""
    if os.path.exists(props):
        with open(props, encoding="latin-1") as fh:
            for line in fh:
                if line.startswith("application.version="):
                    version = line.split("=", 1)[1].strip()
    headless = os.path.join(d, "support", "analyzeHeadless.bat") if os.name == "nt" \
        else os.path.join(d, "support", "analyzeHeadless")
    info.update(version=version or None, headless=os.path.exists(headless),
                java_min=_java_min(props))
    return bool(version and os.path.exists(headless)), version, info


def _java_min(props: str) -> str | None:
    if not os.path.exists(props):
        return None
    with open(props, encoding="latin-1") as fh:
        for line in fh:
            if line.startswith("application.java.min="):
                return line.split("=", 1)[1].strip()
    return None


def rea_report() -> dict:
    node = shutil.which("node")
    if not node or not os.path.exists(REA_MJS):
        return {"found": False, "path": None}
    ok, ver = run([node, REA_MJS, "--version"], 30)
    return {"found": True, "path": REA_MJS, "version": ver if ok else None}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    res: dict[str, dict] = {}

    def add(cid: str, ok: bool, detail: str, fix: str = "") -> None:
        res[cid] = {"ok": ok, "detail": detail, "fix": fix}

    ok, _ = check_py_module("httpx")
    add("capture", ok, "httpx" if ok else "", "pip install httpx websockets cryptography")
    ok1, _ = check_py_module("websockets")
    ok2, _ = check_py_module("cryptography")
    add("static-py", ok1 and ok2, "websockets+cryptography" if ok1 and ok2 else "",
        "pip install websockets cryptography")
    ok, v = run(["capa", "--version"]) if shutil.which("capa") else (False, "")
    add("capa", ok, v, "pip install flare-capa")
    ok, v = run(["floss", "--version"]) if shutil.which("floss") else (False, "")
    add("floss", ok, v, "pip install flare-floss")

    g_ok, g_ver, g_info = ghidra_report()
    add("ghidra", g_ok, g_ver or (g_info.get("install_dir") or ""),
        "download Ghidra 12.1.x, extract, set GHIDRA_INSTALL_DIR + JAVA_HOME(21+)")

    ida = find_exe(["ida", "idat", "ida64", "idat64"], [
        r"C:\tools\IDA93\ida.exe", r"C:\Program Files\IDA Professional 9.3\ida.exe"])
    ida_extra = ""
    if ida:
        inst = os.path.dirname(ida)
        reg = os.environ.get("REA_IDA_MCP_CONFIG", "")
        idalib = os.path.isdir(os.path.join(inst, "idalib", "python"))
        cmd = ""
        if reg and os.path.exists(reg):
            try:
                cmd = (json.load(open(reg, encoding="utf-8")) or {}).get("command", "")
            except Exception:  # noqa: BLE001
                cmd = ""
        ida_extra = (f"idalib={'y' if idalib else 'n'} "
                     f"rea_reg={'y' if cmd else 'n'}")
        ok = bool(reg and cmd)
        add("ida", ok, f"{inst} {ida_extra}" if ok else f"{inst} {ida_extra}",
            "set REA_IDA_MCP_CONFIG to a registration running idalib-mcp --stdio")
    else:
        add("ida", False, "", "install IDA Pro; then set REA_IDA_MCP_CONFIG")

    r2 = find_exe(["rizin", "radare2", "r2"], [
        r"C:\tools\rizin\rizin-win-installer-clang_cl-64\bin\rizin.exe"])
    add("rizin", bool(r2), r2 or "", "install rizin (or radare2) and add to PATH")

    jar = os.environ.get("REA_JADX_MCP_JAR", "")
    jar_ok = bool(jar) and os.path.exists(jar)
    jar_sha = ""
    if jar_ok:
        with open(jar, "rb") as fh:
            jar_sha = hashlib.sha256(fh.read()).hexdigest()
    add("jadx", jar_ok, f"{os.path.basename(jar)} sha256:{jar_sha[:12]}..." if jar_ok else "",
        "set REA_JADX_MCP_JAR to jadx-headless-mcp-0.7.1-all.jar (REA pins 6e5eacf5…)")

    apk = os.environ.get("REA_APKTOOL_COMMAND", "") or find_exe(["apktool"])
    apk_ok = bool(apk) and (os.path.exists(apk) if os.path.isabs(apk) else True)
    add("apktool", apk_ok, apk, "set REA_APKTOOL_COMMAND to apktool.jar wrapper")

    fr = find_exe(["frida"])
    add("frida", bool(fr), fr or "", "pip install frida-tools")

    dbg = find_exe(["x64dbg", "x32dbg"], [
        r"C:\tools\x64dbg\release\x64\x64dbg.exe",
        r"C:\Program Files\x64dbg\release\x64\x64dbg.exe"])
    add("x64dbg", bool(dbg), dbg or "", "install x64dbg; expose via x64dbg-mcp if you want it agentic")

    bw = find_exe(["binwalk"])
    if not bw:
        import subprocess as _sp
        try:
            r = _sp.run(["wsl", "-d", "Ubuntu", "--", "bash", "-lc", "which binwalk"],
                        capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                bw = r.stdout.strip() + " (wsl)"
        except Exception:  # noqa: BLE001
            pass
    add("binwalk", bool(bw), bw or "",
        "Linux-only tool: `wsl -d Ubuntu -- sudo apt install binwalk` (or VS Build Tools + "
        "cargo install binwalk for the native v3). REA's firmware tools expect it on Linux anyway")

    kuna = os.environ.get("REA_KUNA_COMMAND", "") or find_exe(["kuna"], [
        os.path.join(os.getcwd(), "kuna", "decompiler", "target", "release", "kuna.exe"),
        os.path.join(os.getcwd(), "study", "kuna", "decompiler", "target", "release", "kuna.exe")])
    add("kuna", bool(kuna and os.path.exists(kuna)), kuna or "",
        "build: cd study/kuna && make binaries (needs MSVC Build Tools); then set REA_KUNA_COMMAND")

    ts = find_exe(["tshark"], [r"C:\Program Files\Wireshark\tshark.exe"])
    add("tshark", bool(ts), ts or "", "install Wireshark; REA uses REA_TSHARK_COMMAND or PATH")

    adb = find_exe(["adb"])
    add("adb", bool(adb), adb or "", "install platform-tools; set REA_ADB_PATH")

    dn = find_exe(["dotnet"])
    add("dotnet", bool(dn), dn or "", "install .NET SDK")

    rea = rea_report()

    if a.json:
        print(json.dumps({"capabilities": res, "rea": rea,
                          "ghidra": g_info, "java_home": os.environ.get("JAVA_HOME")},
                         indent=1))
        return 0

    print(f"{'capability':<22}{'state':<7}detail / fix")
    print("-" * 96)
    for cid, label, unlocks in CAPABILITIES:
        r = res.get(cid, {"ok": False, "detail": "", "fix": ""})
        state = "OK" if r["ok"] else "MISS"
        detail = r["detail"] or r["fix"]
        print(f"{label:<22}{state:<7}{detail[:62]}")
        if not r["ok"] and r.get("fix") and r["fix"] != detail:
            print(f"{'':<29}fix: {r['fix'][:62]}")

    print("\n--- analysis stack ---")
    print(f"rea:        {'v' + rea['version'] if rea.get('version') else 'not found'}  {rea.get('path') or ''}")
    print(f"ghidra:     {g_info.get('version') or '-'}  {g_info.get('install_dir') or '-'}")
    print(f"java_home:  {os.environ.get('JAVA_HOME') or '-'} (needs JDK 21+ for Ghidra 12.1)")

    usable = [c for c, _, _ in CAPABILITIES if res.get(c, {}).get("ok")]
    blocked = [c for c, _, _ in CAPABILITIES if not res.get(c, {}).get("ok")]
    print(f"\nusable:  {', '.join(usable) or 'none'}")
    print(f"missing: {', '.join(blocked) or 'none'}")
    print("\nA missing engine is not a blocker for the web/JS/Electron lanes — "
          "capture + bundle scan run on stdlib alone.")
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
