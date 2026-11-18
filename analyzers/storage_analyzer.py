import re

from analyzers.dex_scan import const_strings, iter_app_methods, pretty_class

PATTERNS = {
    "STORAGE_WORLD_READABLE":  re.compile(r"MODE_WORLD_READABLE"),
    "STORAGE_WORLD_WRITEABLE": re.compile(r"MODE_WORLD_WRITEABLE"),
    "STORAGE_EXTERNAL":        re.compile(r"getExternalStorageDirectory|getExternalFilesDir"),
    "STORAGE_LOG_SENSITIVE":   re.compile(r"(?i)Log\.(d|e|i|w|v)\([^)]*(password|token|secret|key)"),
}

_PREF_KEY = re.compile(
    r"(?i)^[A-Za-z0-9_.]{0,40}(password|passwd|secret)[A-Za-z0-9_.]{0,24}$"
)
_LOG_PHRASE = re.compile(r"(?i)password\s*is:|updated password from|passwd\s*[:=]")
_LOG_CONTEXT = re.compile(r"(?i)credit\s*card|card\s*number|\bcvv\b|\bssn\b")
_LOG_MSG = re.compile(r"(?i)error|exception|fail")

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
                # External-storage and log hits are decided from app call sites below.
                # The string pool also contains Play Services getExternalFilesDir.
                if rule in ("STORAGE_EXTERNAL", "STORAGE_LOG_SENSITIVE"):
                    continue
                if pat.search(s):
                    L.append(f"  [!] {rule}: {s[:100]}")
                    _emit(rule, s[:100])

    for class_name, method_name, insns in iter_app_methods(ctx):
        invokes = "\n".join(output for op, output in insns if "invoke" in op)
        literals = const_strings(insns)
        where = f"{pretty_class(class_name)}->{method_name}"
        if "getExternalStorageDirectory" in invokes or "getExternalStoragePublicDirectory" in invokes:
            _emit("STORAGE_EXTERNAL", f"{where} getExternalStorageDirectory")
        elif "getExternalFilesDir" in invokes:
            _emit("STORAGE_EXTERNAL", f"{where} getExternalFilesDir")
        logs = "->println(" in invokes or "android/util/Log" in invokes
        leaked = any(_LOG_PHRASE.search(item) for item in literals) or any(
            _LOG_CONTEXT.search(item) and _LOG_MSG.search(item) for item in literals
        )
        if logs and leaked:
            _emit("STORAGE_LOG_SENSITIVE", f"{where} logs a password, card, or other secret")
        writes_pref = "Editor;->putString" in invokes or "SharedPreferences$Editor;->putString" in invokes
        if writes_pref:
            keys = [item for item in literals if _PREF_KEY.match(item)]
            if keys:
                _emit("STORAGE_PREF_SECRET", f"{where} keys: {', '.join(keys[:4])}")
        # DIVA part 3 writes credentials with createTempFile + FileWriter.
        if "createTempFile" in invokes and "FileWriter" in invokes:
            _emit("STORAGE_TEMP_FILE", f"{where} createTempFile + FileWriter")
        if "SQLiteDatabase;->execSQL" in invokes or "SQLiteDatabase;->insert" in invokes:
            if any(re.search(r"(?i)\bpassword\b", item) for item in literals):
                _emit("STORAGE_SQLITE_SECRET", f"{where} SQL mentions a password column")

    if not F:
        L.append("  [-] No world-accessible storage patterns found.")
    return {"tool": "storage", "output": "\n".join(L), "findings": F}

