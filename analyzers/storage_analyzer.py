import re

PATTERNS = {
    "STORAGE_WORLD_READABLE":  re.compile(r"MODE_WORLD_READABLE"),
    "STORAGE_WORLD_WRITEABLE": re.compile(r"MODE_WORLD_WRITEABLE"),
    "STORAGE_EXTERNAL":        re.compile(r"getExternalStorageDirectory|getExternalFilesDir"),
    "STORAGE_LOG_SENSITIVE":   re.compile(r"(?i)Log\.(d|e|i|w|v)\([^)]*(password|token|secret|key)"),
}

def run(ctx):
    L, F = ["=== Storage Analysis ==="], []
    seen = set()
    emitted = set()

    def _emit(rule, evidence):
        key = (rule, evidence[:50])
        if key in emitted:
            return
        emitted.add(key)
        F.append({"rule_id": rule, "evidence": evidence})

    for d in ctx.dex:
        try: strings = d.get_strings()
        except Exception: continue
        for s in strings:
            if not isinstance(s, str) or s in seen: continue
            seen.add(s)
            for rule, pat in PATTERNS.items():
                if pat.search(s):
                    L.append(f"  [!] {rule}: {s[:100]}")
                    _emit(rule, s[:100])
    if not F:
        L.append("  [-] No world-accessible storage patterns found.")
    return {"tool": "storage", "output": "\n".join(L), "findings": F}

