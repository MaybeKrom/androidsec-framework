"""Detect SSL pinning presence and insecure TLS customizations."""

import re

from analyzers.dex_scan import iter_dex_strings, zip_text_files

PIN_PATTERNS = {
    "SSL_PINNING_OKHTTP": re.compile(r"CertificatePinner|okhttp3\.CertificatePinner"),
    "SSL_PINNING_NSC": re.compile(r"pin-set|pin-sha256", re.IGNORECASE),
    # Behavioral TrustAll only — bare checkServerTrusted is every X509TrustManager.
    "SSL_TRUST_ALL": re.compile(
        r"(?i)TrustAll(?:Certs?)?|trustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|"
        r"TrustAllHostnameVerifier|NullHostnameVerifier|EmptyTrustManager|"
        r"NaiveTrustManager|InsecureTrustManager"
    ),
    "SSL_CUSTOM_TRUSTMANAGER": re.compile(r"X509TrustManager|TrustManagerFactory"),
}

_LIBRARY_NOISE = re.compile(
    r"(?i)(?:okhttp3?|okio|conscrypt|org\.conscrypt|com\.android\.org\.conscrypt|"
    r"kotlinx?|androidx\.|com\.google\.|com\.squareup\.|org\.bouncycastle)"
)


def _is_library_noise(text: str) -> bool:
    if _LIBRARY_NOISE.search(text):
        return True
    if re.fullmatch(r"[\(\)\[L/;a-zA-Z0-9$_]+;", (text or "").strip()):
        return True
    return False


def run(ctx):
    lines, findings = ["=== SSL Pinning Analyzer ==="], []
    seen_rules = set()
    trust_all_app_local = False

    for text in iter_dex_strings(ctx):
        for rule, pat in PIN_PATTERNS.items():
            if rule in seen_rules:
                continue
            if not pat.search(text):
                continue
            # Pinning markers often live inside OkHttp itself — still useful inventory.
            if rule in ("SSL_TRUST_ALL",) and _is_library_noise(text):
                continue
            if rule == "SSL_CUSTOM_TRUSTMANAGER" and _is_library_noise(text):
                # Interface refs in libraries are noise; keep app-local customizations.
                continue
            seen_rules.add(rule)
            findings.append({"rule_id": rule, "evidence": text[:140]})
            marker = "+" if "PINNING" in rule else "!"
            lines.append(f"  [{marker}] {rule}: {text[:100]}")
            if rule == "SSL_TRUST_ALL":
                trust_all_app_local = True

    # Parse network security config XML if present in APK.
    for name, text in zip_text_files(ctx, suffixes=(".xml",)):
        if "network_security_config" not in name.lower() and "<network-security-config" not in text:
            continue
        lines.append(f"  [cfg] {name}")
        if re.search(r'cleartextTrafficPermitted\s*=\s*"true"', text):
            findings.append({
                "rule_id": "SSL_NSC_CLEARTEXT",
                "evidence": f"{name}: cleartextTrafficPermitted=true",
            })
            lines.append("  [!] SSL_NSC_CLEARTEXT")
        if "pin-set" in text or "pin-sha256" in text:
            if "SSL_PINNING_NSC" not in seen_rules:
                findings.append({"rule_id": "SSL_PINNING_NSC", "evidence": name})
                lines.append("  [+] SSL_PINNING_NSC in XML")
        if 'src="user"' in text or "trust-anchors" in text:
            findings.append({
                "rule_id": "SSL_NSC_USER_CA",
                "evidence": f"{name}: user CA trust-anchor",
            })
            lines.append("  [!] SSL_NSC_USER_CA")

    # Conflict only when TrustAll evidence is app-local (not library coexistence).
    rules = {f["rule_id"] for f in findings}
    if trust_all_app_local and "SSL_TRUST_ALL" in rules and (
        "SSL_PINNING_OKHTTP" in rules or "SSL_PINNING_NSC" in rules
    ):
        findings.append({
            "rule_id": "SSL_PINNING_BYPASS_CONFLICT",
            "evidence": "Pinning indicators co-exist with app-local TrustAll / hostname bypass",
        })
        lines.append("  [!] SSL_PINNING_BYPASS_CONFLICT")

    if not findings:
        lines.append("  [-] No pinning or TLS customization markers found.")
    return {"tool": "ssl_pinning", "output": "\n".join(lines), "findings": findings}
