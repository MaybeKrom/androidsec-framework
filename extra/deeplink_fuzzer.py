"""Enumerate browsable deep links and emit concrete am start PoC commands."""

NS = "{http://schemas.android.com/apk/res/android}"


def run(ctx):
    lines, findings = ["=== Deep Link Fuzzer / PoC Generator ==="], []
    root = ctx.get_manifest_root()
    if root is None:
        lines.append("  [!] Could not parse Manifest.")
        return {"tool": "deeplink_fuzzer", "output": "\n".join(lines), "findings": []}

    app = root.find("application")
    if app is None:
        lines.append("  [-] No application node.")
        return {"tool": "deeplink_fuzzer", "output": "\n".join(lines), "findings": []}

    seen = set()
    for child in app:
        if child.tag not in ("activity", "activity-alias", "service", "receiver"):
            continue
        comp = child.get(f"{NS}name", "Unknown")
        for itf in child.findall("intent-filter"):
            cats = [k.get(f"{NS}name") or "" for k in itf.findall("category")]
            if not any("BROWSABLE" in c for c in cats):
                continue
            findings.append({"rule_id": "DEEPLINK_BROWSABLE", "evidence": comp})
            lines.append(f"  [!] Browsable: {comp}")
            for data in itf.findall("data"):
                scheme = data.get(f"{NS}scheme") or ""
                host = data.get(f"{NS}host") or ""
                path = data.get(f"{NS}path") or data.get(f"{NS}pathPrefix") or data.get(f"{NS}pathPattern") or "/"
                if not scheme:
                    continue
                uri = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
                if uri in seen:
                    continue
                seen.add(uri)
                poc = f'adb shell am start -a android.intent.action.VIEW -d "{uri}"'
                findings.append({"rule_id": "DEEPLINK_POC", "evidence": poc})
                lines.append(f"      PoC: {poc}")
                if scheme == "http":
                    findings.append({"rule_id": "DEEPLINK_HTTP", "evidence": uri})
                if host in ("", "*", None):
                    findings.append({"rule_id": "DEEPLINK_WILDCARD_HOST", "evidence": uri})

    if not findings:
        lines.append("  [-] No browsable intent filters (deep links) found.")
    else:
        lines.insert(1, f"Browsable surfaces / PoCs: {len(findings)}")
    return {"tool": "deeplink_fuzzer", "output": "\n".join(lines), "findings": findings}
