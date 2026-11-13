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
    "NETWORK_HTTP_URL",
}


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
    for item in out:
        item.pop("_collapse_count", None)
    return out
