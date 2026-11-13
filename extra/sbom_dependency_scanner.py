"""Lightweight SBOM / dependency fingerprinting from APK zip + DEX strings."""

import re

from analyzers.dex_scan import iter_dex_strings

KNOWN_LIBS = {
    "okhttp3/": ("OkHttp3", "NETWORK"),
    "okhttp/": ("OkHttp", "NETWORK"),
    "retrofit2/": ("Retrofit2", "NETWORK"),
    "com/squareup/picasso": ("Picasso", "MEDIA"),
    "com/bumptech/glide": ("Glide", "MEDIA"),
    "com/google/gson": ("Gson", "DATA"),
    "org/json/": ("org.json", "DATA"),
    "kotlinx/coroutines": ("Kotlin Coroutines", "RUNTIME"),
    "io/reactivex": ("RxJava", "RUNTIME"),
    "com/google/firebase": ("Firebase", "CLOUD"),
    "com/amazonaws/": ("AWS SDK", "CLOUD"),
    "com/facebook/": ("Facebook SDK", "THIRD_PARTY"),
    "io/fabric": ("Fabric/Crashlytics", "TELEMETRY"),
    "com/crashlytics": ("Crashlytics", "TELEMETRY"),
    "org/apache/http": ("Apache HttpClient legacy", "NETWORK"),
}

VERSION_HINT = re.compile(r"(?i)(okhttp|retrofit|gson|glide)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)")


def run(ctx):
    lines, findings = ["=== SBOM / Dependency Scanner ==="], []
    found = {}

    # Paths inside APK often include library packages.
    try:
        for name in ctx.zip.namelist():
            for needle, (lib, category) in KNOWN_LIBS.items():
                if needle in name.replace("\\", "/"):
                    found[lib] = category
    except Exception:
        pass

    for text in iter_dex_strings(ctx, max_strings=80_000):
        for needle, (lib, category) in KNOWN_LIBS.items():
            if needle in text:
                found[lib] = category
        for match in VERSION_HINT.finditer(text):
            evidence = match.group(0)
            findings.append({
                "rule_id": "SBOM_VERSION_HINT",
                "evidence": evidence[:120],
            })

    if "Apache HttpClient legacy" in found:
        findings.append({
            "rule_id": "SBOM_LEGACY_HTTPCLIENT",
            "evidence": "org.apache.http references present",
        })
    if "Firebase" in found:
        findings.append({
            "rule_id": "SBOM_FIREBASE_PRESENT",
            "evidence": "Firebase SDK fingerprints detected",
        })
    if "AWS SDK" in found:
        findings.append({
            "rule_id": "SBOM_AWS_SDK_PRESENT",
            "evidence": "AWS SDK fingerprints detected",
        })

    lines.append(f"Libraries fingerprint matched: {len(found)}")
    for lib, category in sorted(found.items()):
        lines.append(f"  [+] {lib} ({category})")
        findings.append({
            "rule_id": "SBOM_LIBRARY_PRESENT",
            "evidence": f"{lib} ({category})",
        })

    if not found:
        lines.append("  [-] No well-known third-party fingerprints matched.")
    return {"tool": "sbom", "output": "\n".join(lines), "findings": findings}
