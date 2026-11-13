import re


# Behavioral / insecure-usage markers — not bare API type references from OkHttp/Conscrypt.
CODE_PATTERNS = {
    "CODE_WEAK_CRYPTO_ECB":   re.compile(r"AES/ECB"),
    "CODE_WEAK_CRYPTO_DES":   re.compile(r"(?i)DES/(CBC|ECB)"),
    "CODE_WEAK_HASH_MD5":     re.compile(r"(?i)MessageDigest.*MD5|MD5.*MessageDigest"),
    "CODE_WEAK_HASH_SHA1":    re.compile(r"(?i)MessageDigest.*SHA-?1|SHA-?1.*MessageDigest"),
    # Require construction / usage — bare Ljava/util/Random; is WebSocket-masking noise.
    "CODE_INSECURE_RANDOM":   re.compile(
        r"new\s+Random\s*\(|Ljava/util/Random;-><init>|java\.util\.Random\("
    ),
    # Require TrustAll-style markers — checkServerTrusted alone is every X509TrustManager.
    "CODE_TRUST_ALL_CERTS":   re.compile(
        r"(?i)TrustAll(?:Certs?)?|trustAllCerts|ACCEPT_ALL_CERT|"
        r"EmptyTrustManager|NaiveTrustManager|InsecureTrustManager|"
        r"checkServerTrusted[\s\S]{0,40}return\s*;"
    ),
    # Require allow-all / always-true verifier — bare HostnameVerifier is library API noise.
    "CODE_HOSTNAME_VERIFIER": re.compile(
        r"(?i)ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllHostnameVerifier|"
        r"NullHostnameVerifier|InsecureHostnameVerifier|"
        r"HostnameVerifier[\s\S]{0,60}return\s+true"
    ),
}

# Positive controls: presence means the app tries to defend against a technique.
# Word-bound / package-path patterns — avoid ExposedDropdownMenu / kotlinx TLD noise.
RESILIENCE_PATTERNS = {
    "RESILIENCE_ROOT_CHECK_PRESENT":   re.compile(
        r"RootDetection|isDeviceRooted|isRooted|/su\b|test-keys|Superuser\.apk|Superuser",
        re.IGNORECASE),
    "RESILIENCE_FRIDA_CHECK_PRESENT":  re.compile(
        r"frida-server|frida-agent|gum-js-loop|\bfrida\b|libfrida", re.IGNORECASE),
    "RESILIENCE_XPOSED_CHECK_PRESENT": re.compile(
        r"de\.robv\.android\.xposed|XposedBridge|\bXposedHelpers\b|\bXposed\b"),
    "RESILIENCE_DEBUG_CHECK_PRESENT":  re.compile(
        r"isDebuggerConnected|waitForDebugger|android\.os\.Debug"),
    "RESILIENCE_EMULATOR_CHECK_PRESENT": re.compile(
        r"goldfish|ranchu|generic_x86|qemu", re.IGNORECASE),
}

# Third-party / framework namespaces commonly present as DEX strings.
_LIBRARY_NOISE = re.compile(
    r"(?i)(?:^|[/.\s])"
    r"(?:okhttp3?|okio|conscrypt|org\.conscrypt|com\.android\.org\.conscrypt|"
    r"kotlinx?|androidx\.|com\.google\.|com\.squareup\.|io\.reactivex|"
    r"org\.apache\.|org\.bouncycastle|net\.sqlcipher|"
    r"com\.facebook\.|io\.flutter|com\.unity3d)"
)

MAX_STRINGS = 200_000


def _is_library_noise(s: str) -> bool:
    """True when the string is clearly a third-party / framework artifact."""
    if _LIBRARY_NOISE.search(s):
        return True
    # Pure JVM type descriptors without insecure markers (e.g. ()Ljavax/net/ssl/HostnameVerifier;).
    if re.fullmatch(r"[\(\)\[L/;a-zA-Z0-9$_]+;", s.strip()) and "TrustAll" not in s:
        return True
    return False


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

            if _is_library_noise(s):
                continue

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
