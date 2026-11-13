"""Dynamic UI dump — capture current activity hierarchy for lab challenge coverage."""

import re
import subprocess
import time

from analyzers.utils import device_ready


def run(ctx):
    lines, findings = ["=== UI Automator Explorer ==="], []
    ok, reason = device_ready()
    if not ok:
        lines.append(f"[!] {reason} — SKIPPED")
        return {
            "tool": "uiautomator",
            "output": "\n".join(lines),
            "findings": [],
            "skipped": True,
        }

    try:
        package = ctx.apk.get_package()
    except Exception:
        package = ""

    try:
        subprocess.run(
            ["adb", "shell", "monkey", "-p", package, "-c",
             "android.intent.category.LAUNCHER", "1"],
            capture_output=True, timeout=15,
        )
        time.sleep(2)
        dump = subprocess.run(
            ["adb", "shell", "uiautomator", "dump", "/sdcard/androsec_ui.xml"],
            capture_output=True, text=True, timeout=20,
        )
        pull = subprocess.run(
            ["adb", "shell", "cat", "/sdcard/androsec_ui.xml"],
            capture_output=True, text=True, timeout=20,
        )
        xml = pull.stdout or ""
    except Exception as exc:
        lines.append(f"[!] UI dump failed: {exc}")
        return {
            "tool": "uiautomator",
            "output": "\n".join(lines),
            "findings": [],
            "skipped": True,
        }

    if not xml.strip():
        lines.append("[-] Empty UI hierarchy (uiautomator may be unavailable on this image).")
        findings.append({
            "rule_id": "UI_DUMP_UNAVAILABLE",
            "evidence": (dump.stdout or dump.stderr or "empty")[:200],
        })
        return {"tool": "uiautomator", "output": "\n".join(lines), "findings": findings}

    texts = re.findall(r'text="([^"]{2,80})"', xml)
    descs = re.findall(r'content-desc="([^"]{2,80})"', xml)
    labels = []
    for item in texts + descs:
        if item not in labels:
            labels.append(item)

    lines.append(f"UI labels captured: {len(labels)}")
    challenge_like = []
    keywords = (
        "insecure", "storage", "logging", "hardcod", "input", "access",
        "network", "root", "emulator", "biometric", "webview", "sql",
        "validation", "side channel", "binary",
    )
    for label in labels[:80]:
        lines.append(f"  • {label}")
        low = label.lower()
        if any(k in low for k in keywords):
            challenge_like.append(label)

    if challenge_like:
        findings.append({
            "rule_id": "UI_CHALLENGE_MENU",
            "evidence": "; ".join(challenge_like[:12]),
        })
        lines.append(f"[+] Challenge-like UI entries: {len(challenge_like)}")
    else:
        findings.append({
            "rule_id": "UI_HIERARCHY_CAPTURED",
            "evidence": f"{len(labels)} labels from uiautomator dump",
        })

    return {"tool": "uiautomator", "output": "\n".join(lines), "findings": findings}
