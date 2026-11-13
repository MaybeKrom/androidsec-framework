"""Map known intentionally vulnerable lab apps to challenge inventories."""

from __future__ import annotations

LAB_PROFILES = {
    "jakhar.aseem.diva": {
        "name": "DIVA",
        "challenges": [
            ("INSECURE_LOGGING", "Insecure logging of credentials"),
            ("HARDCODING_PART1", "Hardcoded credentials / validation"),
            ("INSECURE_STORAGE_1", "Insecure data storage (SharedPreferences)"),
            ("INSECURE_STORAGE_2", "Insecure data storage (SQLite)"),
            ("INSECURE_STORAGE_3", "Insecure data storage (files)"),
            ("INSECURE_STORAGE_4", "Insecure data storage (external)"),
            ("INPUT_VALIDATION_1", "Input validation / SQL injection"),
            ("INPUT_VALIDATION_2", "Input validation issues"),
            ("ACCESS_CONTROL_1", "Access control / exported components"),
            ("ACCESS_CONTROL_2", "Access control issues"),
            ("ACCESS_CONTROL_3", "Access control / provider"),
            ("HARDCODING_PART2", "Hardcoding issues part 2"),
            ("INPUT_VALIDATION_3", "Input validation part 3"),
        ],
    },
    "owasp.sat.agoat": {
        "name": "AndroGoat",
        "challenges": [
            ("NETWORK_INTERCEPTING", "Network intercepting / cleartext / SSL"),
            ("UNPROTECTED_COMPONENTS", "Unprotected Android components"),
            ("INSECURE_DATA_STORAGE", "Insecure data storage"),
            ("INPUT_VALIDATIONS", "Input validations"),
            ("SIDE_CHANNEL", "Side channel data leakage"),
            ("HARDCODE_ISSUES", "Hardcode issues"),
            ("ROOT_DETECTION", "Root detection"),
            ("EMULATOR_DETECTION", "Emulator detection"),
            ("BINARY_PATCHING", "Binary patching surface"),
            ("BIOMETRIC", "Biometric authentication issues"),
        ],
    },
    "com.android.insecurebankv2": {
        "name": "InsecureBankv2",
        "challenges": [
            ("WEBVIEW_JS_BRIDGE", "Exported WebView + JS bridge"),
            ("EXPORTED_PROVIDER", "TrackUserContentProvider"),
            ("DEBUGGABLE_CREDS", "Debuggable credential storage"),
            ("BROADCAST", "Insecure broadcast receiver"),
            ("HTTP_API", "HTTP / cleartext API usage"),
        ],
    },
    "owasp.mstg.uncrackable1": {
        "name": "UnCrackable Level 1",
        "challenges": [("ROOT_BYPASS", "Root detection + secret string")],
    },
    "owasp.mstg.uncrackable2": {
        "name": "UnCrackable Level 2",
        "challenges": [("NATIVE_SECRET", "Native secret verification")],
    },
    "owasp.mstg.uncrackable3": {
        "name": "UnCrackable Level 3",
        "challenges": [("ANTI_FRIDA", "Anti-Frida + native checks")],
    },
    "com.app.damnvulnerablebank": {
        "name": "Damn Vulnerable Bank",
        "challenges": [
            ("AUTH_ISSUES", "Authentication / session issues"),
            ("API_SECURITY", "Backend API security"),
            ("STORAGE", "Insecure storage"),
            ("WEBVIEW", "WebView risks"),
        ],
    },
}


def run(ctx):
    lines, findings = ["=== Lab Challenge Mapper ==="], []
    try:
        package = ctx.apk.get_package() or ""
    except Exception:
        package = ""

    profile = LAB_PROFILES.get(package)
    if not profile:
        # Fuzzy match common lab names in package.
        for key, value in LAB_PROFILES.items():
            if key.split(".")[-1] in package or package in key:
                profile = value
                package = key
                break

    if not profile:
        lines.append(f"Package {package or '?'}: no built-in lab profile.")
        lines.append("Supported: DIVA, AndroGoat, InsecureBankv2, UnCrackable 1-3, DamnVulnerableBank.")
        return {"tool": "lab_mapper", "output": "\n".join(lines), "findings": []}

    lines.append(f"Detected lab app: {profile['name']} ({package})")
    lines.append(f"Challenges mapped: {len(profile['challenges'])}")
    findings.append({
        "rule_id": "LAB_APP_DETECTED",
        "evidence": f"{profile['name']} ({package})",
    })
    for challenge_id, title in profile["challenges"]:
        findings.append({
            "rule_id": "LAB_CHALLENGE",
            "evidence": f"[{profile['name']}] {challenge_id}: {title}",
        })
        lines.append(f"  [lab] {challenge_id} — {title}")

    lines.append(
        "Note: LAB_CHALLENGE rows are inventory for assessment coverage — "
        "pair with static/dynamic tools and AI exploit for confirmation."
    )
    return {"tool": "lab_mapper", "output": "\n".join(lines), "findings": findings}
