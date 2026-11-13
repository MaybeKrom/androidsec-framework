import re
import subprocess

from analyzers.utils import device_ready as _device_ready

PATTERNS = {
    "LOG_SENSITIVE_PASSWORD": re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
    "LOG_SENSITIVE_TOKEN":    re.compile(r"(?i)(token|apikey|api_key|secret)\s*[=:]\s*\S+"),
    # Strict CC regex: 16 digits with optional spaces/dashes
    "LOG_CREDIT_CARD":        re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "LOG_EMAIL":              re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
}

BLOCKLIST = (
    "vndksupport", "SurfaceFlinger", "AppWindowToken", "ActivityManager",
    "libc", "WindowManager", "graphics.mapper", "OpenGLRenderer", "ProcessStatsService",
    "F/DEBUG", "tombstone", "DEBUGGER", "rax ", "rbx ", "rcx ", "rdx ",
)


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def run(ctx):
    L, F = ["=== Log Analyzer ==="], []
    ok, reason = _device_ready()
    if not ok:
        L.append(f"[!] {reason} — SKIPPED")
        return {"tool": "log", "output": "\n".join(L), "findings": [], "skipped": True}

    try:
        out = subprocess.run(["adb", "logcat", "-d", "-v", "brief"], capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        L.append(f"[!] logcat error: {e}")
        return {"tool": "log", "output": "\n".join(L), "findings": [], "skipped": True}

    lines = out.splitlines()
    for line in lines:
        if any(bl in line for bl in BLOCKLIST):
            continue

        for rule, pat in PATTERNS.items():
            match = pat.search(line)
            if not match:
                continue
            if rule == "LOG_CREDIT_CARD" and not _luhn_ok(match.group(0)):
                continue
            snippet = line[:180]
            L.append(f"  [!] {rule}: {snippet}")
            F.append({"rule_id": rule, "evidence": snippet})

    L.insert(1, f"Logcat lines: {len(lines)}")
    return {"tool": "log", "output": "\n".join(L), "findings": F}
