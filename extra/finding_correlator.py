"""Correlate related weakness patterns into higher-signal attack-chain findings."""

import re

from analyzers.dex_scan import iter_dex_strings

NS = "{http://schemas.android.com/apk/res/android}"


def run(ctx):
    lines, findings = ["=== Finding Correlator ==="], []
    signals = set()
    evidence = {}

    # Manifest signals
    root = ctx.get_manifest_root()
    if root is not None:
        app = root.find("application")
        if app is not None:
            if (app.get(f"{NS}debuggable") or "").lower() == "true":
                signals.add("debuggable")
            if (app.get(f"{NS}allowBackup") or "true").lower() == "true":
                signals.add("backup")
            if (app.get(f"{NS}usesCleartextTraffic") or "").lower() == "true":
                signals.add("cleartext")
            for child in app:
                exported = child.get(f"{NS}exported")
                has_filter = len(child.findall("intent-filter")) > 0
                is_exported = (exported == "true") or (exported is None and has_filter)
                if not is_exported:
                    continue
                if child.tag == "provider":
                    signals.add("exported_provider")
                    evidence["exported_provider"] = child.get(f"{NS}name", "provider")
                if child.tag in ("activity", "activity-alias"):
                    signals.add("exported_activity")
                    evidence.setdefault("exported_activity", child.get(f"{NS}name", "activity"))

    # DEX signals
    for text in iter_dex_strings(ctx, max_strings=120_000):
        if "addJavascriptInterface" in text:
            signals.add("js_bridge")
            evidence["js_bridge"] = text[:100]
        if re.search(r"(?i)rawQuery|execSQL", text):
            signals.add("sql_api")
        if re.search(r"(?i)SharedPreferences|getSharedPreferences", text):
            signals.add("prefs")
        if re.search(r"(?i)password|passwd", text) and "prefs" in signals:
            signals.add("password_string")
        if "MODE_WORLD_READABLE" in text or "MODE_WORLD_WRITEABLE" in text:
            signals.add("world_file")
        if re.search(r"AKIA[0-9A-Z]{16}", text):
            signals.add("aws_key")
            evidence["aws_key"] = text[:40]

    chains = []
    if "js_bridge" in signals and "exported_activity" in signals:
        chains.append((
            "CORRELATED_WEBVIEW_EXPORT",
            "Exported activity + addJavascriptInterface — attacker-reachable JS bridge surface",
            f"{evidence.get('exported_activity')} + {evidence.get('js_bridge', 'js bridge')}",
        ))
    if "exported_provider" in signals and "sql_api" in signals:
        chains.append((
            "CORRELATED_PROVIDER_SQL",
            "Exported ContentProvider with SQLite APIs — injection / data leak candidate",
            evidence.get("exported_provider", "provider"),
        ))
    if "debuggable" in signals and ("prefs" in signals or "password_string" in signals):
        chains.append((
            "CORRELATED_DEBUG_STORAGE",
            "Debuggable app with SharedPreferences/password strings — run-as credential theft path",
            "debuggable + prefs/password",
        ))
    if "cleartext" in signals and "aws_key" in signals:
        chains.append((
            "CORRELATED_CLEARTEXT_SECRET",
            "Cleartext traffic permitted while cloud credentials exist in the client",
            evidence.get("aws_key", "secret"),
        ))
    if "backup" in signals and "prefs" in signals:
        chains.append((
            "CORRELATED_BACKUP_PREFS",
            "Backup allowed with SharedPreferences usage — adb backup data extraction path",
            "allowBackup + SharedPreferences",
        ))
    if "world_file" in signals:
        chains.append((
            "CORRELATED_WORLD_STORAGE",
            "World-readable/writable file modes present",
            "MODE_WORLD_*",
        ))

    lines.append(f"Signals: {', '.join(sorted(signals)) or 'none'}")
    for rule, title, ev in chains:
        findings.append({"rule_id": rule, "evidence": f"{title} | {ev}"})
        lines.append(f"  [!] {rule}: {title}")

    if not chains:
        lines.append("  [-] No multi-signal attack chains correlated.")
    return {"tool": "finding_correlator", "output": "\n".join(lines), "findings": findings}
