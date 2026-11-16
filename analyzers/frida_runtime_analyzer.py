"""Frida runtime hooks for lab apps — prefs, crypto, and best-effort SSL unpin.

Prefer Genymotion / official emulator / rooted phone over android-x86.
Keeps graceful skip when Frida or the device is unavailable.
"""

from __future__ import annotations

import os
import subprocess
import time


def _force_stop(pkg: str) -> None:
    subprocess.run(["adb", "shell", "am", "force-stop", pkg], capture_output=True, timeout=10)


def _launch(pkg: str) -> None:
    subprocess.run(
        [
            "adb", "shell", "monkey", "-p", pkg,
            "-c", "android.intent.category.LAUNCHER", "1",
        ],
        capture_output=True,
        timeout=15,
    )


def _pidof(pkg: str) -> int | None:
    out = subprocess.run(
        ["adb", "shell", "pidof", pkg],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    if not out:
        return None
    try:
        return int(out.split()[0])
    except ValueError:
        return None


def _attach_session(frida, pkg: str, lines: list) -> tuple:
    """Attach by PID with spawn fallback.

    Returns (device, session, spawned_pid_or_none). Caller must resume(spawned)
    after script.load() when spawned_pid is set.
    """
    dev = frida.get_usb_device(timeout=8)

    # Attempt 1–2: launch + attach by PID (more reliable on some emulators).
    for attempt in range(1, 3):
        _force_stop(pkg)
        time.sleep(0.5)
        lines.append(f"Launch attempt {attempt} via ADB monkey…")
        _launch(pkg)
        time.sleep(4 + attempt * 2)
        pid = _pidof(pkg)
        if not pid:
            lines.append("[!] pidof returned empty")
            continue
        lines.append(f"Found PID: {pid} — attaching…")
        try:
            session = dev.attach(pid)
            return dev, session, None
        except Exception as exc:
            lines.append(f"[!] Attach to PID {pid} failed: {exc}")

    # Attempt 3: spawn (resume after hooks load — better for early pinning).
    lines.append("Trying Frida spawn fallback…")
    try:
        _force_stop(pkg)
        time.sleep(0.4)
        spawned = dev.spawn([pkg])
        session = dev.attach(spawned)
        return dev, session, spawned
    except Exception as exc:
        lines.append(f"[!] Spawn failed: {exc}")
        raise


def run(ctx):
    lines, findings = ["=== Frida Runtime Analyzer ==="], []
    try:
        import frida
    except ImportError:
        lines.append("[!] frida-python not installed — SKIPPED")
        return {"tool": "frida", "output": "\n".join(lines), "findings": [], "skipped": True}

    try:
        try:
            pkg = ctx.apk.get_package()
        except Exception:
            lines.append("[!] Could not determine package name — SKIPPED")
            return {"tool": "frida", "output": "\n".join(lines), "findings": [], "skipped": True}

        lines.append(f"Target package: {pkg}")
        lines.append(
            "[i] Prefer Genymotion / official emulator / rooted phone for Frida "
            "(android-x86 is often flaky)."
        )

        try:
            device, session, spawned = _attach_session(frida, pkg, lines)
        except Exception as exc:
            lines.append(f"[!] Frida attach/spawn unavailable: {exc}")
            findings.append({
                "rule_id": "RUNTIME_FRIDA_ATTACH_FAILED",
                "evidence": str(exc)[:200],
            })
            return {
                "tool": "frida",
                "output": "\n".join(lines),
                "findings": findings,
                "skipped": True,
            }

        lines.append("Attached — injecting runtime_monitor.js…")
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "scripts",
            "runtime_monitor.js",
        )
        with open(script_path, "r", encoding="utf-8") as handle:
            js_code = handle.read()

        script = session.create_script(js_code)
        frida_logs: list[str] = []

        def on_message(message, data):
            try:
                if not isinstance(message, dict):
                    return
                mtype = message.get("type", "")
                if mtype == "send":
                    frida_logs.append(str(message.get("payload", "")))
                elif mtype == "error":
                    frida_logs.append(f"[Frida Error] {message.get('stack', '')}")
            except Exception:
                pass

        script.on("message", on_message)
        script.load()

        if spawned is not None:
            try:
                device.resume(spawned)
                lines.append(f"Resumed spawned PID {spawned}")
            except Exception as exc:
                lines.append(f"[!] Resume warning: {exc}")

        listen_s = int(os.environ.get("ANDROSEC_FRIDA_SECONDS", "12") or "12")
        lines.append(
            f"\nListening for runtime events ({listen_s}s)… "
            "Interact with the app now (login / network actions help SSL hooks)."
        )
        time.sleep(max(6, listen_s))

        try:
            session.detach()
        except Exception:
            pass

        if frida_logs:
            lines.append(f"\nCaptured {len(frida_logs)} Frida events:")
            for log in frida_logs[:60]:
                lines.append(f"  {log}")

            for log in frida_logs:
                if "[SharedPreferences] Saved" in log:
                    findings.append({"rule_id": "RUNTIME_PREF_PASSWORD", "evidence": log})
                elif "[Crypto] Cipher Algorithm" in log:
                    findings.append({"rule_id": "RUNTIME_CRYPTO", "evidence": log})
                elif "[SSL-Unpin]" in log and "bypassed" in log.lower():
                    findings.append({"rule_id": "RUNTIME_SSL_UNPIN", "evidence": log})
                elif "[HTTP] URL.openConnection" in log:
                    findings.append({"rule_id": "RUNTIME_HTTP_URL", "evidence": log})
                    if "http://" in log.lower():
                        findings.append({
                            "rule_id": "RUNTIME_HTTP_CLEARTEXT",
                            "evidence": log,
                        })
        else:
            lines.append(
                "  [-] No Frida events captured. Did you interact with the app? "
                "Confirm frida-server matches frida-tools on Genymotion/emulator/rooted phone."
            )

    except Exception as exc:
        lines.append(f"[!] Frida runtime error: {exc}")

    return {"tool": "frida", "output": "\n".join(lines), "findings": findings}
