"""Enumerate exported components and emit Intent / provider abuse candidates."""

NS = "{http://schemas.android.com/apk/res/android}"


def run(ctx):
    lines, findings = ["=== Intent Abuse Analyzer ==="], []
    root = ctx.get_manifest_root()
    if root is None:
        return {
            "tool": "intent_abuse",
            "output": "Could not parse manifest",
            "findings": [],
        }
    app = root.find("application")
    if app is None:
        return {"tool": "intent_abuse", "output": "No <application>", "findings": []}

    try:
        package = ctx.apk.get_package() or ""
    except Exception:
        package = ""

    sensitive_actions = {
        "android.provider.Telephony.SMS_RECEIVED",
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.NEW_OUTGOING_CALL",
        "android.intent.action.PACKAGE_ADDED",
        "android.intent.action.USER_PRESENT",
    }

    for child in app:
        if child.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        name = child.get(f"{NS}name", "Unknown")
        exported = child.get(f"{NS}exported")
        perm = child.get(f"{NS}permission", "")
        has_filter = len(child.findall("intent-filter")) > 0
        is_exported = (exported == "true") or (exported is None and has_filter)
        if not is_exported:
            continue

        if name.startswith("."):
            full = f"{package}{name}"
        else:
            full = name

        actions = []
        categories = []
        for itf in child.findall("intent-filter"):
            for action in itf.findall("action"):
                actions.append(action.get(f"{NS}name") or "")
            for cat in itf.findall("category"):
                categories.append(cat.get(f"{NS}name") or "")

        if child.tag == "provider":
            authorities = child.get(f"{NS}authorities") or child.get(f"{NS}authority") or ""
            read_perm = child.get(f"{NS}readPermission", "none")
            write_perm = child.get(f"{NS}writePermission", "none")
            evidence = (
                f"{full} authorities={authorities} permission={perm or 'none'} "
                f"read={read_perm} write={write_perm}"
            )
            findings.append({"rule_id": "INTENT_EXPORTED_PROVIDER", "evidence": evidence})
            if authorities:
                uri = f"content://{authorities.split(';')[0].strip()}"
                findings.append({
                    "rule_id": "INTENT_PROVIDER_POC",
                    "evidence": f"adb shell content query --uri {uri}",
                })
                lines.append(f"  [!] provider {full} → {uri}")
            else:
                lines.append(f"  [!] provider {full} (no authority attribute)")
            continue

        is_launcher = (
            "android.intent.action.MAIN" in actions
            and "android.intent.category.LAUNCHER" in categories
        )
        if is_launcher and child.tag in ("activity", "activity-alias"):
            continue

        if not perm:
            findings.append({
                "rule_id": "INTENT_EXPORTED_UNPROTECTED",
                "evidence": f"{child.tag}:{full} actions={actions[:4]}",
            })
            if child.tag in ("activity", "activity-alias"):
                component = name if name.startswith(".") else full
                findings.append({
                    "rule_id": "INTENT_ACTIVITY_POC",
                    "evidence": f"adb shell am start -n {package}/{component}",
                })
            lines.append(f"  [!] unprotected {child.tag}: {full}")

        for action in actions:
            if action in sensitive_actions:
                findings.append({
                    "rule_id": "INTENT_SENSITIVE_ACTION",
                    "evidence": f"{full} listens for {action}",
                })
                lines.append(f"  [!] sensitive action {action} → {full}")

    if not findings:
        lines.append("  [-] No unprotected exported Intent surfaces detected.")
    else:
        lines.insert(1, f"Candidates: {len(findings)}")
    return {"tool": "intent_abuse", "output": "\n".join(lines), "findings": findings}
