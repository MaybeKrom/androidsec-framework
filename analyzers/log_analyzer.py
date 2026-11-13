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

# Framework / instrumentation noise — UI dumpers print password= fields for every EditText.
BLOCKLIST = (
    "vndksupport", "SurfaceFlinger", "AppWindowToken", "ActivityManager",
    "libc", "WindowManager", "graphics.mapper", "OpenGLRenderer", "ProcessStatsService",
    "F/DEBUG", "tombstone", "DEBUGGER", "rax ", "rbx ", "rcx ", "rdx ",
    "AccessibilityNodeInfoDumper", "UIAutomator", "UiAutomator", "uiautomator",
    "Instrumentation", "Monkey", "EventsInjected", "InputDispatcher",
    "chre", "StatsLog", "auditd",
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


def _package_pids(package: str) -> list[str]:
    if not package:
        return []
    pids = []
    for cmd in (
        ["adb", "shell", "pidof", package],
        ["adb", "shell", "pidof", "-s", package],
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout.strip()
        except Exception:
            continue
        for tok in out.replace("\n", " ").split():
            if tok.isdigit() and tok not in pids:
                pids.append(tok)
        if pids:
            break
    return pids


def _fetch_logcat(package: str) -> tuple[str, str]:
    """Return (log text, mode note). Prefer PID-scoped dump when package is known."""
    pids = _package_pids(package)
    if pids:
        chunks = []
        for pid in pids[:4]:
            try:
                chunk = subprocess.run(
                    ["adb", "logcat", "-d", "-v", "brief", "--pid", pid],
                    capture_output=True, text=True, timeout=20,
                ).stdout
            except Exception as exc:
                return "", f"logcat --pid error: {exc}"
            if chunk:
                chunks.append(chunk)
        if chunks:
            return "\n".join(chunks), f"pid-filtered ({','.join(pids[:4])})"
        # Fall through: process may have exited — package-tag filter on full dump.
    try:
        out = subprocess.run(
            ["adb", "logcat", "-d", "-v", "brief"],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except Exception as e:
        return "", f"logcat error: {e}"
    if not package:
        return out, "full-dump (no package)"
    # Keep lines that mention the package (tag or message) — still narrower than global.
    kept = [ln for ln in out.splitlines() if package in ln]
    return "\n".join(kept), f"package-substring filter ({package})"


def run(ctx):
    L, F = ["=== Log Analyzer ==="], []
    ok, reason = _device_ready()
    if not ok:
        L.append(f"[!] {reason} — SKIPPED")
        return {"tool": "log", "output": "\n".join(L), "findings": [], "skipped": True}

    package = ""
    try:
        package = ctx.apk.get_package() or ""
    except Exception:
        package = ""

    out, mode = _fetch_logcat(package)
    if mode.startswith("logcat") and "error" in mode:
        L.append(f"[!] {mode}")
        return {"tool": "log", "output": "\n".join(L), "findings": [], "skipped": True}

    L.append(f"Scope: {mode}")
    lines = out.splitlines() if out else []
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
