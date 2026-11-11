import subprocess
import time

from analyzers.utils import device_ready as _device_ready

def run(ctx):
    L, F = ["=== Runtime Inspector ==="], []
    ok, reason = _device_ready()
    if not ok:
        L.append(f"[!] {reason} — SKIPPED")
        return {"tool": "runtime", "output": "\n".join(L), "findings": [], "skipped": True}

    pkg = ctx.apk.get_package()
    try:
        subprocess.run(["adb", "logcat", "-c"], capture_output=True, timeout=8)
        subprocess.run(
            ["adb", "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
            capture_output=True, timeout=15)
        time.sleep(5)
        out = subprocess.run(["adb", "logcat", "-d", "-v", "brief"], capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        L.append(f"[!] runtime error: {e}")
        return {"tool": "runtime", "output": "\n".join(L), "findings": [], "skipped": True}

    crashes = 0
    for line in out.splitlines():
        # ONLY flag actual fatal exceptions, ignore monkey/runtimeinit noise
        if "FATAL EXCEPTION" in line or "AndroidRuntime: Process:" in line:
            crashes += 1
            L.append(f"  [!] {line[:200]}")
            F.append({"rule_id": "RUNTIME_CRASH", "evidence": line[:200]})
        elif ">>> START com.android" in line or "Calling main entry" in line:
            # Log it for visibility but do not flag as a finding
            L.append(f"  [-] launch trace: {line[:100]}")

    L.insert(1, f"Logcat lines: {len(out.splitlines())} | Crashes: {crashes}")
    return {"tool": "runtime", "output": "\n".join(L), "findings": F}
