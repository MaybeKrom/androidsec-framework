import re

from analyzers.dex_scan import const_strings, iter_app_methods, pretty_class


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

    # Call-site checks. String-pool search misses these because the literals
    # and the API call live in separate const-string instructions.
    backdoor_re = re.compile(r"(?i)^(/devlogin|/backdoor|devadmin)$")
    sms_secret_re = re.compile(r"(?i)password\s*is:|updated password from")
    compare_secret_re = re.compile(r"^[A-Za-z0-9]{12,40}$")
    api_secret_re = re.compile(r"(?i)(api password|api key)\s*[:=]")
    card_insert_re = re.compile(r"(?i)insert\s+into")
    pan_re = re.compile(r"\b\d{13,19}\b")
    for class_name, method_name, insns in iter_app_methods(ctx):
        literals = const_strings(insns)
        invokes = "\n".join(output for op, output in insns if "invoke" in op)
        where = f"{pretty_class(class_name)}->{method_name}"
        backdoor = [item for item in literals if backdoor_re.search(item.strip())]
        if backdoor and ("HttpPost" in invokes or "->equals(" in invokes):
            evidence = f"{where} literals: {', '.join(backdoor)}"
            if "AUTH_HARDCODED_BACKDOOR" not in emitted:
                emitted["AUTH_HARDCODED_BACKDOOR"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "AUTH_HARDCODED_BACKDOOR", "evidence": evidence})
                L.append(f"  [!] AUTH_HARDCODED_BACKDOOR: {evidence}")
        if "sendTextMessage" in invokes and any(sms_secret_re.search(item) for item in literals):
            evidence = f"{where} sends an SMS that includes the password"
            if "BROADCAST_SMS_SECRET" not in emitted:
                emitted["BROADCAST_SMS_SECRET"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "BROADCAST_SMS_SECRET", "evidence": evidence})
                L.append(f"  [!] BROADCAST_SMS_SECRET: {evidence}")
        # Client-side secret check: edit text compared to a long literal.
        if "->equals(" in invokes and ("getText(" in invokes or "EditText" in invokes):
            secrets = [
                item for item in literals
                if compare_secret_re.match(item)
                and item.lower() not in {"password", "username", "vendorkey"}
            ]
            if secrets and "HARDCODED_COMPARE_SECRET" not in emitted:
                evidence = f"{where} compares input to {secrets[0]}"
                emitted["HARDCODED_COMPARE_SECRET"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "HARDCODED_COMPARE_SECRET", "evidence": evidence})
                L.append(f"  [!] HARDCODED_COMPARE_SECRET: {evidence}")
        api_hits = [item.replace("\n", " ")[:120] for item in literals if api_secret_re.search(item)]
        if api_hits:
            evidence = f"{where}: {api_hits[0]}"
            key = ("HARDCODED_API_CREDENTIAL", evidence[:80])
            if key not in emitted:
                emitted[key] = {"count": 1}
                F.append({"rule_id": "HARDCODED_API_CREDENTIAL", "evidence": evidence})
                L.append(f"  [!] HARDCODED_API_CREDENTIAL: {evidence}")
        card_hits = [item for item in literals if card_insert_re.search(item) and pan_re.search(item)]
        if card_hits and "HARDCODED_PAYMENT_DATA" not in emitted:
            evidence = f"{where}: {card_hits[0][:120]}"
            emitted["HARDCODED_PAYMENT_DATA"] = {"count": 1, "evidence": evidence}
            F.append({"rule_id": "HARDCODED_PAYMENT_DATA", "evidence": evidence})
            L.append(f"  [!] HARDCODED_PAYMENT_DATA: {evidence}")
        if "endsWith(" in invokes:
            hosts = [
                item for item in literals
                if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", item.strip("."))
                or item.strip() in {"example.com", "example.com."}
            ]
            if hosts and "DEEPLINK_HOST_SUFFIX" not in emitted:
                evidence = f"{where} uses endsWith on {hosts[0]}"
                emitted["DEEPLINK_HOST_SUFFIX"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "DEEPLINK_HOST_SUFFIX", "evidence": evidence})
                L.append(f"  [!] DEEPLINK_HOST_SUFFIX: {evidence}")
        if "sendBroadcast" in invokes and any(
            re.search(r"(?i)credential|password|token", item) for item in literals
        ):
            evidence = f"{where} broadcasts a credential-related intent"
            if "BROADCAST_SENSITIVE" not in emitted:
                emitted["BROADCAST_SENSITIVE"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "BROADCAST_SENSITIVE", "evidence": evidence})
                L.append(f"  [!] BROADCAST_SENSITIVE: {evidence}")
        if "getParcelableExtra" in invokes and any("redirect" in item.lower() for item in literals):
            evidence = f"{where} reads a nested intent extra"
            if "INTENT_REDIRECT" not in emitted:
                emitted["INTENT_REDIRECT"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "INTENT_REDIRECT", "evidence": evidence})
                L.append(f"  [!] INTENT_REDIRECT: {evidence}")
        world_path = any(
            item.startswith("/sdcard") or item.startswith("/storage") for item in literals
        )
        if "DexClassLoader" in invokes and world_path and "CODE_DYNAMIC_DEX_LOAD" not in emitted:
            evidence = f"{where} loads a DEX/APK from external storage"
            emitted["CODE_DYNAMIC_DEX_LOAD"] = {"count": 1, "evidence": evidence}
            F.append({"rule_id": "CODE_DYNAMIC_DEX_LOAD", "evidence": evidence})
            L.append(f"  [!] CODE_DYNAMIC_DEX_LOAD: {evidence}")
        if "createPackageContext" in invokes and "loadClass" in invokes and "CODE_FOREIGN_PLUGIN_LOAD" not in emitted:
            evidence = f"{where} loads classes from another installed package"
            emitted["CODE_FOREIGN_PLUGIN_LOAD"] = {"count": 1, "evidence": evidence}
            F.append({"rule_id": "CODE_FOREIGN_PLUGIN_LOAD", "evidence": evidence})
            L.append(f"  [!] CODE_FOREIGN_PLUGIN_LOAD: {evidence}")
        if "getBooleanExtra" in invokes and any(api_secret_re.search(item) for item in literals):
            evidence = f"{where} shows credentials unless a boolean intent extra is set"
            if "INTENT_BOOLEAN_BYPASS" not in emitted:
                emitted["INTENT_BOOLEAN_BYPASS"] = {"count": 1, "evidence": evidence}
                F.append({"rule_id": "INTENT_BOOLEAN_BYPASS", "evidence": evidence})
                L.append(f"  [!] INTENT_BOOLEAN_BYPASS: {evidence}")

    return {"tool": "static_code", "output": "\n".join(L), "findings": F}
