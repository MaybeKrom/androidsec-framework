"""Find hardcoded crypto keys / IVs and weak Cipher.getInstance strings."""

import re

from analyzers.dex_scan import iter_dex_strings

CIPHER_PAT = re.compile(r"(?i)AES/(ECB|CBC|GCM|CTR)/[A-Za-z0-9]+|DES/|DESede/")
KEY_ASSIGN = re.compile(
    r"(?i)(?:secret[_-]?key|aes[_-]?key|encryption[_-]?key|iv|init[_-]?vector)"
    r"\s*[=:]\s*[\"']([^\"']{4,128})[\"']"
)
HEX_KEY = re.compile(r"\b[0-9a-fA-F]{16,64}\b")


def run(ctx):
    lines, findings = ["=== Crypto Key Analyzer ==="], []
    emitted = set()
    cipher_hits = []

    for text in iter_dex_strings(ctx):
        for match in CIPHER_PAT.finditer(text):
            algo = match.group(0)
            if algo not in cipher_hits:
                cipher_hits.append(algo)
                if re.search(r"(?i)ECB|/DES", algo):
                    rule = "CRYPTO_WEAK_TRANSFORM"
                else:
                    rule = "CRYPTO_TRANSFORM_FOUND"
                findings.append({"rule_id": rule, "evidence": algo})
                lines.append(f"  [!] {rule}: {algo}")

        for _match in KEY_ASSIGN.finditer(text):
            evidence = text[:160]
            key = ("CRYPTO_HARDCODED_KEY", evidence[:50])
            if key in emitted:
                continue
            emitted.add(key)
            findings.append({"rule_id": "CRYPTO_HARDCODED_KEY", "evidence": evidence})
            lines.append(f"  [!] CRYPTO_HARDCODED_KEY: {evidence[:120]}")

        if re.search(r"(?i)\b(key|secret|password)\b", text) and HEX_KEY.search(text):
            blob = HEX_KEY.search(text).group(0)
            if 16 <= len(blob) <= 64:
                k = ("CRYPTO_HEX_KEY_CANDIDATE", blob)
                if k not in emitted:
                    emitted.add(k)
                    findings.append({
                        "rule_id": "CRYPTO_HEX_KEY_CANDIDATE",
                        "evidence": f"{blob} in: {text[:80]}",
                    })
                    lines.append(f"  [?] CRYPTO_HEX_KEY_CANDIDATE: {blob}")

    if cipher_hits:
        lines.insert(1, f"Cipher transforms: {', '.join(cipher_hits[:8])}")
    if not findings:
        lines.append("  [-] No hardcoded key / weak transform candidates found.")
    return {"tool": "crypto_key", "output": "\n".join(lines), "findings": findings}
