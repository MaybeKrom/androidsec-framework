import re


CODE_PATTERNS = {
    "CODE_WEAK_CRYPTO_ECB":   re.compile(r"AES/ECB"),
    "CODE_WEAK_CRYPTO_DES":   re.compile(r"(?i)DES/(CBC|ECB)"),
    "CODE_WEAK_HASH_MD5":     re.compile(r"(?i)MessageDigest.*MD5|MD5.*MessageDigest"),
    "CODE_WEAK_HASH_SHA1":    re.compile(r"(?i)MessageDigest.*SHA-?1|SHA-?1.*MessageDigest"),
    "CODE_INSECURE_RANDOM":   re.compile(r"Ljava/util/Random;"),
    "CODE_TRUST_ALL_CERTS":   re.compile(r"checkServerTrusted"),
    "CODE_HOSTNAME_VERIFIER": re.compile(r"HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER"),
}

# Positive controls: presence means the app tries to defend against a technique.
RESILIENCE_PATTERNS = {
    "RESILIENCE_ROOT_CHECK_PRESENT":   re.compile(
        r"RootDetection|isDeviceRooted|isRooted|/su\b|test-keys|Superuser\.apk|Superuser",
        re.IGNORECASE),
    "RESILIENCE_FRIDA_CHECK_PRESENT":  re.compile(
        r"frida-server|frida-agent|gum-js-loop|Frida|gmain", re.IGNORECASE),
    "RESILIENCE_XPOSED_CHECK_PRESENT": re.compile(
        r"de\.robv\.android\.xposed|XposedBridge|Xposed", re.IGNORECASE),
    "RESILIENCE_DEBUG_CHECK_PRESENT":  re.compile(
        r"isDebuggerConnected|waitForDebugger|android\.os\.Debug"),
    "RESILIENCE_EMULATOR_CHECK_PRESENT": re.compile(
        r"goldfish|ranchu|generic_x86|qemu", re.IGNORECASE),
}

MAX_STRINGS = 200_000


def run(ctx):
    L, F = ["=== Static Code Scan ==="], []
    seen = set()
    scanned = 0

    # One finding per rule for these pattern scanners — AndroGoat/DIVA otherwise
    # emit 10+ HostnameVerifier / Frida-check rows that are the same issue.
    emitted = {}

    def _emit(rule, evidence):
        if rule in emitted:
            emitted[rule]["count"] += 1
            return
        emitted[rule] = {"count": 1, "evidence": evidence}
        F.append({"rule_id": rule, "evidence": evidence})

    for d in ctx.dex:
        try:
            strings = d.get_strings()
        except Exception:
            continue

        for s in strings:
            if not isinstance(s, str) or s in seen:
                continue
            seen.add(s)
            scanned += 1
            if scanned >= MAX_STRINGS:
                break

            for rule, pat in CODE_PATTERNS.items():
                if pat.search(s):
                    L.append(f"  [!] {rule}: {s[:100]}")
                    _emit(rule, s[:100])

            for rule, pat in RESILIENCE_PATTERNS.items():
                if pat.search(s):
                    L.append(f"  [+] {rule}: {s[:100]}")
                    _emit(rule, s[:100])

    L.insert(1, f"Strings scanned: {scanned}")

    # Annotate collapsed match counts on evidence for the report.
    for f in F:
        meta = emitted.get(f["rule_id"]) or {}
        n = int(meta.get("count") or 1)
        if n > 1:
            f["evidence"] = f"{f['evidence']}  (+{n - 1} similar matches collapsed)"

    # Summary of detected controls
    controls = [f for f in F if f["rule_id"].startswith("RESILIENCE_")]
    if controls:
        L.append(f"\nResilience controls detected: {len(controls)}")
        for f in controls:
            L.append(f"  - {f['rule_id'].replace('RESILIENCE_', '').replace('_PRESENT', '')}"
                     f"  (evidence: {f['evidence'][:60]})")
    else:
        L.append("\nNo resilience controls detected (no root/frida/xposed/debug/emulator checks).")

    return {"tool": "static_code", "output": "\n".join(L), "findings": F}
