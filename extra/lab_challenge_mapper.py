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
            ("EXPORTED_ACTIVITIES", "Exported PostLogin, DoTransfer, ViewStatement, ChangePassword"),
            ("WEBVIEW_FILE", "ViewStatement loads external HTML with JavaScript"),
            ("EXPORTED_PROVIDER", "TrackUserContentProvider query without a read permission"),
            ("BROADCAST_SMS", "MyBroadCastReceiver sends the new password by SMS"),
            ("HARDCODED_AES", "Hardcoded AES passphrase in CryptoClass"),
            ("DEV_LOGIN", "Developer backdoor /devlogin with devadmin"),
            ("DEBUGGABLE_CREDS", "Debuggable app stores credentials in SharedPreferences"),
            ("CLEARTEXT_HTTP", "Login and transfer clients use http://"),
            ("ROOT_CHECK", "Client-side root check in PostLogin"),
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
    "oversecured.ovaa": {
        "name": "OVAA",
        "challenges": [
            ("DEEPLINK_LOGIN_URL", "Deeplink overwrites the login URL"),
            ("DEEPLINK_GRANT_URI", "Deeplink grants URI permission to a non-exported provider"),
            ("DEEPLINK_WEBVIEW", "Deeplink opens a URL in a file-access WebView"),
            ("HOST_SUFFIX", "Host check uses endsWith and can be bypassed"),
            ("INTENT_REDIRECT", "LoginActivity starts a caller-supplied intent"),
            ("FILE_PICK", "ACTION_PICK result is trusted as a file"),
            ("BROADCAST_CREDS", "Implicit broadcast carries credentials"),
            ("DYNAMIC_DEX", "DexClassLoader loads /sdcard/updater.apk"),
            ("PLUGIN_LOAD", "Loads code from other installed plugin packages"),
            ("FILEPROVIDER_ROOT", "FileProvider exposes root-path"),
        ],
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
        lines.append("Supported: DIVA, AndroGoat, InsecureBankv2, OVAA, UnCrackable 1-3, DamnVulnerableBank.")
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
