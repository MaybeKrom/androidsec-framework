"""Inspect native .so libraries for interesting security strings / JNI exports."""

import re
from zipfile import ZipFile

MAX_SO = 3 * 1024 * 1024

INTERESTING = re.compile(
    r"(?i)(frida|xposed|substrate|ptrace|anti.?debug|/su\b|magisk|rootcloak|"
    r"JNI_OnLoad|AES/ECB|password|secret|api[_-]?key)"
)


def _strings(data, min_len=6):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def run(ctx):
    lines, findings = ["=== Native Security Analyzer ==="], []
    try:
        zf = ctx.zip
    except Exception as exc:
        return {
            "tool": "native_security",
            "output": f"zip open failed: {exc}",
            "findings": [],
        }

    so_files = [n for n in zf.namelist() if n.endswith(".so")]
    lines.append(f"Native libraries: {len(so_files)}")
    for name in so_files[:40]:
        try:
            info = zf.getinfo(name)
            if info.file_size > MAX_SO:
                lines.append(f"  [-] skip large {name} ({info.file_size} bytes)")
                continue
            data = zf.read(name)
        except Exception:
            continue
        strings = _strings(data, 8)
        hits = [s for s in strings if INTERESTING.search(s)]
        lines.append(f"  [.so] {name}: {len(data)} bytes, interesting={len(hits)}")
        for hit in hits[:8]:
            rule = "NATIVE_ANTI_ANALYSIS" if re.search(
                r"(?i)frida|xposed|ptrace|anti.?debug|magisk|/su\b", hit
            ) else "NATIVE_SENSITIVE_STRING"
            findings.append({"rule_id": rule, "evidence": f"{name}: {hit[:120]}"})
            lines.append(f"      [!] {rule}: {hit[:100]}")
        if b"JNI_OnLoad" in data:
            findings.append({
                "rule_id": "NATIVE_JNI_ONLOAD",
                "evidence": name,
            })

    if not so_files:
        lines.append("  [-] No .so libraries in APK.")
    elif not findings:
        lines.append("  [-] No high-signal native strings matched.")
    return {"tool": "native_security", "output": "\n".join(lines), "findings": findings}
