"""Shared DEX string helpers for analyzers."""

from __future__ import annotations


def iter_dex_strings(ctx, max_strings: int = 200_000):
    """Yield unique DEX strings up to max_strings."""
    seen = set()
    count = 0
    for dex in getattr(ctx, "dex", None) or []:
        try:
            strings = dex.get_strings()
        except Exception:
            continue
        if not isinstance(strings, (list, tuple)):
            continue
        for value in strings:
            if not isinstance(value, str) or value in seen:
                continue
            seen.add(value)
            yield value
            count += 1
            if count >= max_strings:
                return


def scan_patterns(ctx, patterns: dict, max_strings: int = 200_000):
    """Return list of {rule_id, evidence} for first match of each (rule, evidence[:80])."""
    findings = []
    emitted = set()
    for text in iter_dex_strings(ctx, max_strings=max_strings):
        for rule, pattern in patterns.items():
            if not pattern.search(text):
                continue
            evidence = text[:120]
            key = (rule, evidence[:80])
            if key in emitted:
                continue
            emitted.add(key)
            findings.append({"rule_id": rule, "evidence": evidence})
    return findings


def zip_text_files(ctx, suffixes=(".xml", ".json", ".properties", ".txt", ".html")):
    """Yield (name, text) for small text-like entries inside the APK zip."""
    try:
        names = ctx.zip.namelist()
    except Exception:
        return
    for name in names:
        lower = name.lower()
        if not any(lower.endswith(suf) for suf in suffixes):
            continue
        try:
            info = ctx.zip.getinfo(name)
            if info.file_size > 512_000:
                continue
            raw = ctx.zip.read(name)
        except Exception:
            continue
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if text.strip():
            yield name, text
