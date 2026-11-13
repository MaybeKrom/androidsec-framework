import re


PATTERNS = {
    "SECRET_AWS_KEY":            re.compile(r"AKIA[0-9A-Z]{16}"),
    "SECRET_GOOGLE_API":         re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "SECRET_FIREBASE":           re.compile(r"AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}"),
    "SECRET_PRIVATE_KEY":        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
    "SECRET_BEARER":             re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    "SECRET_JWT":                re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "SECRET_SLACK":              re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "SECRET_STRIPE":             re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "SECRET_GITHUB":             re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "SECRET_HARDCODED_PASSWORD": re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']([^\"']{4,64})[\"']"),
    "SECRET_IP_ADDRESS":         re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# 24+ hex chars = hash-like or obfuscated blob (UnCrackable XOR key is exactly this).
HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{24,}\b")

# Only scan .so files up to this size (large game engines etc. are skipped)
MAX_SO_BYTES = 2 * 1024 * 1024
# Hard cap on strings to prevent pathological APKs from hanging the scan
MAX_STRINGS = 200_000


def _mask(s):
    return s if len(s) <= 60 else s[:57] + "..."


def _strings_from_bytes(data, min_len=6):
    """Extract printable ASCII strings from a binary blob."""
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def run(ctx):
    L, F = ["=== Secret Detection ==="], []
    seen_strings = set()
    seen_findings = set()

    def _emit(rule, evidence):
        key = (rule, evidence[:50])
        if key in seen_findings:
            return
        seen_findings.add(key)
        F.append({"rule_id": rule, "evidence": evidence})

    # ---- 1. Scan DEX strings ----
    dex_strings = 0
    for d in ctx.dex:
        try:
            for s in d.get_strings():
                if not isinstance(s, str) or s in seen_strings:
                    continue
                seen_strings.add(s)
                dex_strings += 1
                if dex_strings >= MAX_STRINGS:
                    break

                for rule, pat in PATTERNS.items():
                    if pat.search(s):
                        L.append(f"  [!] {rule}: {_mask(s)}")
                        _emit(rule, _mask(s))

                for m in HEX_BLOB.finditer(s):
                    blob = m.group(0)
                    L.append(f"  [?] Possible hex blob: {_mask(blob)}")
                    _emit("SECRET_OBFUSCATED_BLOB", _mask(blob))
        except Exception:
            continue

    L.insert(1, f"DEX strings scanned: {dex_strings}")

    # ---- 1b. Scan assets / res / google-services style configs ----
    try:
        from analyzers.dex_scan import zip_text_files
        for name, text in zip_text_files(ctx):
            if not any(x in name.lower() for x in (
                "asset", "res/raw", "google-services", "firebase", "aws", "secret", "config"
            )) and "AKIA" not in text and "AIza" not in text:
                continue
            for rule, pat in PATTERNS.items():
                if rule in ("SECRET_IP_ADDRESS",):
                    continue
                match = pat.search(text)
                if match:
                    L.append(f"  [cfg] {rule} in {name}")
                    _emit(rule, f"{name}: {_mask(match.group(0))}")
    except Exception as exc:
        L.append(f"  [!] asset/config scan failed: {exc}")

    # ---- 2. Scan native .so files for embedded secrets ----
    so_count = 0
    try:
        for name in ctx.zip.namelist():
            if not name.endswith(".so"):
                continue
            try:
                info = ctx.zip.getinfo(name)
                if info.file_size > MAX_SO_BYTES:
                    L.append(f"  [-] {name}: skipped (>{MAX_SO_BYTES // 1024}KB)")
                    continue
                data = ctx.zip.read(name)
            except Exception:
                continue

            so_count += 1
            so_strings = _strings_from_bytes(data, 8)
            L.append(f"  [.so] {name}: {len(data)} bytes, {len(so_strings)} strings")

            for s in so_strings:
                for rule, pat in PATTERNS.items():
                    if rule in ("SECRET_IP_ADDRESS",
                                "SECRET_HARDCODED_PASSWORD",
                                "SECRET_BEARER"):
                        # Too noisy inside binaries
                        continue
                    if pat.search(s):
                        L.append(f"      [!] {rule}: {_mask(s)}")
                        _emit("SECRET_IN_NATIVE",
                              f"{name}: {rule}: {_mask(s)}")
    except Exception as e:
        L.append(f"  [!] .so scan failed: {e}")

    L.append(f"\nNative libraries scanned: {so_count}")
    return {"tool": "secret_detector", "output": "\n".join(L), "findings": F}
