import os
import shutil
import subprocess

def _adb(*args, timeout=10):
    return subprocess.run(["adb", *args], capture_output=True,
                          text=True, timeout=timeout)

def choose_serial(text, preferred=""):
    """Return one ready serial. Honor ANDROID_SERIAL only when that device is ready."""
    serials = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    preferred = (preferred or "").strip()
    if preferred:
        if preferred not in serials:
            return None
        return preferred
    return serials[0] if serials else None

def run(ctx):
    L, F = ["=== ADB Device Inspector ==="], []
    if not shutil.which("adb"):
        L.append("[!] adb not on PATH — SKIPPED")
        return {"tool": "adb_inspector", "output": "\n".join(L), "findings": [], "skipped": True}

    try:
        out = _adb("devices").stdout or ""
    except Exception as e:
        L.append(f"[!] adb error: {e}")
        return {"tool": "adb_inspector", "output": "\n".join(L), "findings": [], "skipped": True}

    preferred = os.environ.get("ANDROID_SERIAL", "")
    s = choose_serial(out, preferred)
    if not s:
        if preferred.strip():
            L.append(f"[!] Selected device {preferred.strip()} is not ready — SKIPPED")
        else:
            L.append("[!] No device/emulator attached — SKIPPED")
        return {"tool": "adb_inspector", "output": "\n".join(L), "findings": [], "skipped": True}
    L.append(f"Device: {s}")
    props = {"ro.build.version.release": "Android", "ro.build.version.sdk": "SDK",
             "ro.product.manufacturer": "Manufacturer", "ro.product.model": "Model",
             "ro.product.cpu.abi": "ABI"}
    for p, label in props.items():
        try:
            r = _adb("-s", s, "shell", "getprop", p)
            L.append(f"  {label}: {r.stdout.strip()}")
        except Exception:
            pass

    # Lab environment readiness signals (informational).
    try:
        su = _adb("-s", s, "shell", "which", "su")
        if (su.stdout or "").strip():
            F.append({"rule_id": "ENV_ROOTED_DEVICE", "evidence": su.stdout.strip()})
            L.append("  [i] su binary present")
        frida = _adb("-s", s, "shell", "ps", "-A")
        if "frida" in (frida.stdout or "").lower():
            F.append({"rule_id": "ENV_FRIDA_SERVER", "evidence": "frida process visible in ps"})
            L.append("  [i] frida-related process visible")
    except Exception:
        pass

    pkg = ctx.apk.get_package()
    try:
        if pkg in _adb("-s", s, "shell", "pm", "list", "packages", pkg).stdout:
            L.append(f"  Target app {pkg}: INSTALLED")
            r = _adb("-s", s, "shell", "pm", "path", pkg)
            L.append(f"  APK path: {r.stdout.strip()}")
        else:
            L.append(f"  Target app {pkg}: NOT INSTALLED")
    except Exception as e:
        L.append(f"[!] package check failed: {e}")
    return {"tool": "adb_inspector", "output": "\n".join(L), "findings": F}
