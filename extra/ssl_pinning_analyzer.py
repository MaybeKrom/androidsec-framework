"""Detect SSL pinning presence and insecure TLS customizations."""

import re

from analyzers.dex_scan import iter_dex_strings, zip_text_files

PIN_PATTERNS = {
    "SSL_PINNING_OKHTTP": re.compile(r"CertificatePinner|okhttp3\.CertificatePinner"),
    "SSL_PINNING_NSC": re.compile(r"pin-set|pin-sha256", re.IGNORECASE),
    "SSL_TRUST_ALL": re.compile(r"checkServerTrusted|TrustAll|ALLOW_ALL_HOSTNAME_VERIFIER"),
    "SSL_CUSTOM_TRUSTMANAGER": re.compile(r"X509TrustManager|TrustManagerFactory"),
}


def run(ctx):
    lines, findings = ["=== SSL Pinning Analyzer ==="], []
    seen_rules = set()

    for text in iter_dex_strings(ctx):
        for rule, pat in PIN_PATTERNS.items():
            if rule in seen_rules:
                continue
            if pat.search(text):
                seen_rules.add(rule)
                findings.append({"rule_id": rule, "evidence": text[:140]})
                marker = "+" if "PINNING" in rule else "!"
                lines.append(f"  [{marker}] {rule}: {text[:100]}")

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

    # Conflict: TrustAll + Pinning both present.
    rules = {f["rule_id"] for f in findings}
    if "SSL_TRUST_ALL" in rules and (
        "SSL_PINNING_OKHTTP" in rules or "SSL_PINNING_NSC" in rules
    ):
        findings.append({
            "rule_id": "SSL_PINNING_BYPASS_CONFLICT",
            "evidence": "Pinning indicators co-exist with TrustAll / custom TrustManager",
        })
        lines.append("  [!] SSL_PINNING_BYPASS_CONFLICT")

    if not findings:
        lines.append("  [-] No pinning or TLS customization markers found.")
    return {"tool": "ssl_pinning", "output": "\n".join(lines), "findings": findings}
