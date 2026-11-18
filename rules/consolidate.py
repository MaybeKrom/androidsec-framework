"""Collapse noisy duplicate findings so reports stay readable."""

import re

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
    "NATIVE_HARDCODED_SECRET",
    "NATIVE_JNI_ONLOAD",
    "DEEPLINK_BROWSABLE",
    "SSL_CUSTOM_TRUSTMANAGER",
    "WEBVIEW_JS_ENABLED",
    "RUNTIME_SSL_UNPIN",
    "RUNTIME_HTTP_URL",
    "MITM_TRAFFIC_SUMMARY",
}

# Equivalent findings from overlapping tools — keep the preferred rule id.
_EQUIVALENT_GROUPS = (
    ("MANIFEST_CLEARTEXT", "NETWORK_CLEARTEXT_ALLOWED"),
    # Provider surfaces: keep COMPONENT_PROVIDER; drop authority/intent restates.
    ("COMPONENT_PROVIDER", "COMPONENT_PROVIDER_AUTHORITY"),
    ("COMPONENT_PROVIDER", "INTENT_EXPORTED_PROVIDER"),
    # TrustAll: prefer static_code behavioral hit over ssl_pinning duplicate.
    ("CODE_TRUST_ALL_CERTS", "SSL_TRUST_ALL"),
    # Crypto: prefer CODE_WEAK_CRYPTO_* over generic CRYPTO_WEAK_TRANSFORM.
    ("CODE_WEAK_CRYPTO_ECB", "CRYPTO_WEAK_TRANSFORM"),
    ("CODE_WEAK_CRYPTO_DES", "CRYPTO_WEAK_TRANSFORM"),
)

_COMPONENT_RULES = (
    "COMPONENT_ACTIVITY",
    "COMPONENT_SERVICE",
    "COMPONENT_RECEIVER",
    "COMPONENT_PROVIDER",
    "COMPONENT_LAUNCHER",
)

_FQCN_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,})\b"
)


def _extract_fqcns(text: str) -> set[str]:
    return {m.group(1) for m in _FQCN_RE.finditer(text or "")}


def _drop_intent_component_duplicates(findings: list) -> list:
    """Drop INTENT_EXPORTED_UNPROTECTED when a COMPONENT_* shares the same FQCN."""
    component_fqcns: set[str] = set()
    for finding in findings:
        rule = str(finding.get("rule_id") or "")
        if rule in _COMPONENT_RULES:
            component_fqcns |= _extract_fqcns(str(finding.get("evidence") or ""))
    if not component_fqcns:
        return findings
    out = []
    for finding in findings:
        rule = str(finding.get("rule_id") or "")
        if rule == "INTENT_EXPORTED_UNPROTECTED":
            intent_fqcns = _extract_fqcns(str(finding.get("evidence") or ""))
            if intent_fqcns & component_fqcns:
                continue
            # Remaining INTENT restates without COMPONENT match → demote severity.
            item = dict(finding)
            if str(item.get("severity") or "").lower() in ("critical", "high"):
                item["severity"] = "Medium"
            out.append(item)
            continue
        out.append(finding)
    return out


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

    out = _drop_intent_component_duplicates(out)

    for item in out:
        item.pop("_collapse_count", None)
    return out
