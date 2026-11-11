"""Shared utility functions used across multiple androidsec analyzers."""
import hashlib
import shutil
import subprocess


def sha256_file(path):
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_size(n):
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def device_ready():
    """Check whether an ADB device/emulator is attached and responsive.

    Returns:
        (bool, str): (is_ready, reason_if_not)
    """
    if not shutil.which("adb"):
        return False, "adb not on PATH"
    try:
        r = subprocess.run(
            ["adb", "get-state"], capture_output=True, text=True, timeout=5
        )
        if r.stdout.strip() == "device":
            return True, ""
        return False, "no device/emulator attached"
    except Exception as e:
        return False, f"adb get-state failed: {e}"


def has_network_capability(ctx):
    """Detect whether the APK has networking capability.

    Checks for INTERNET permission first, then scans DEX strings for
    common networking library references.

    Returns:
        (bool, str): (has_capability, reason)
    """
    if "android.permission.INTERNET" in ctx.apk.get_permissions():
        return True, "INTERNET permission declared"

    hints = (
        "okhttp3/", "retrofit2/", "HttpURLConnection",
        "java/net/Socket", "volley/", "Ktor",
    )
    for d in ctx.dex:
        try:
            strings = d.get_strings()
            if not isinstance(strings, (list, tuple)):
                continue
            for s in strings:
                if isinstance(s, str) and any(h in s for h in hints):
                    return True, f"network code reference: {s[:60]}"
        except Exception:
            continue
    return False, "no network capability detected"
