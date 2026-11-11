import shutil, subprocess

def _adb(*args, timeout=10):
    return subprocess.run(["adb", *args], capture_output=True,
                          text=True, timeout=timeout)

def run(ctx):
    L, F = ["=== ADB Device Inspector ==="], []
    if not shutil.which("adb"):
        L.append("[!] adb not on PATH — SKIPPED")
        return {"tool": "adb_inspector", "output": "\n".join(L), "findings": [], "skipped": True}

    try:
        out = _adb("devices").stdout
    except Exception as e:
        L.append(f"[!] adb error: {e}")
        return {"tool": "adb_inspector", "output": "\n".join(L), "findings": [], "skipped": True}

    serials = [l.split("\t")[0] for l in out.splitlines()[1:] if "\tdevice" in l]
    if not serials:
        L.append("[!] No device/emulator attached — SKIPPED")
        return {"tool": "adb_inspector", "output": "\n".join(L), "findings": [], "skipped": True}

    s = serials[0]
    L.append(f"Device: {s}")
    props = {"ro.build.version.release": "Android", "ro.build.version.sdk": "SDK",
             "ro.product.manufacturer": "Manufacturer", "ro.product.model": "Model"}
    for p, label in props.items():
        try:
            r = _adb("-s", s, "shell", "getprop", p)
            L.append(f"  {label}: {r.stdout.strip()}")
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
