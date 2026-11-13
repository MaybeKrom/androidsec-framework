"""Collapse noisy duplicate findings so reports stay readable."""

# Pattern scanners often hit the same class of issue many times with slightly
# different evidence strings. Keep one row per rule for these.
_COLLAPSE_BY_RULE = {
    "CODE_HOSTNAME_VERIFIER",
    "CODE_TRUST_ALL_CERTS",
    "CODE_INSECURE_RANDOM",
    "CODE_WEAK_CRYPTO_ECB",
    "CODE_WEAK_CRYPTO_DES",
    "CODE_WEAK_HASH_MD5",
    "CODE_WEAK_HASH_SHA1",
    "RESILIENCE_ROOT_CHECK_PRESENT",
    "RESILIENCE_FRIDA_CHECK_PRESENT",
    "RESILIENCE_XPOSED_CHECK_PRESENT",
    "RESILIENCE_DEBUG_CHECK_PRESENT",
    "RESILIENCE_EMULATOR_CHECK_PRESENT",
    "STORAGE_EXTERNAL",
    "PERMISSION_STORAGE",
    "PERMISSION_CAMERA",
    "PERMISSION_LOCATION",
    "PERMISSION_SMS",
    "PERMISSION_CONTACTS",
    "PERMISSION_MIC",
    "PERMISSION_PHONE",
    "PERMISSION_SYSTEM",
    "PERMISSION_SENSORS",
    "PERMISSION_CALENDAR",
    "NETWORK_HTTP_URL",
    "SBOM_LIBRARY_PRESENT",
    "SBOM_VERSION_HINT",
    "NATIVE_SENSITIVE_STRING",
    "NATIVE_ANTI_ANALYSIS",
    "DEEPLINK_BROWSABLE",
    "SSL_CUSTOM_TRUSTMANAGER",
    "WEBVIEW_JS_ENABLED",
}

# Equivalent findings from overlapping tools — keep the preferred rule id.
_EQUIVALENT_GROUPS = (
    ("MANIFEST_CLEARTEXT", "NETWORK_CLEARTEXT_ALLOWED"),
    # Provider surfaces: keep COMPONENT_PROVIDER; drop authority/intent restates.
    ("COMPONENT_PROVIDER", "COMPONENT_PROVIDER_AUTHORITY"),
    ("COMPONENT_PROVIDER", "INTENT_EXPORTED_PROVIDER"),
    # TrustAll: prefer static_code behavioral hit over ssl_pinning duplicate.
    ("CODE_TRUST_ALL_CERTS", "SSL_TRUST_ALL"),
)


def consolidate_findings(findings: list) -> list:
    """Return findings with noisy rule duplicates collapsed; order preserved."""
    out = []
    seen = {}
    for finding in findings or []:
        rule = str(finding.get("rule_id") or "")
        evidence = str(finding.get("evidence") or "")
        if rule in _COLLAPSE_BY_RULE:
            key = rule
        else:
            key = (rule, evidence[:120])
        if key in seen:
            idx = seen[key]
            prev = out[idx]
            count = int(prev.get("_collapse_count") or 1) + 1
            prev["_collapse_count"] = count
            if "collapsed" not in str(prev.get("evidence") or "").lower():
                prev["evidence"] = (
                    f"{prev.get('evidence') or evidence}  "
                    f"(+{count - 1} similar matches collapsed)"
                )
            continue
        seen[key] = len(out)
        item = dict(finding)
        item["_collapse_count"] = 1
        out.append(item)

    # Drop secondary duplicates if both exist.
    present = {f.get("rule_id") for f in out}
    drop = set()
    for preferred, secondary in _EQUIVALENT_GROUPS:
        if preferred in present and secondary in present:
            drop.add(secondary)
    # If only INTENT_EXPORTED_PROVIDER exists without COMPONENT_PROVIDER, keep it.
    # If COMPONENT_PROVIDER_AUTHORITY exists without COMPONENT_PROVIDER, keep authority.
    if drop:
        out = [f for f in out if f.get("rule_id") not in drop]

    for item in out:
        item.pop("_collapse_count", None)
    return out
