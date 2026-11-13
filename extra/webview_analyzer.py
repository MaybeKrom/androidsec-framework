import re

def run(ctx):
    L, F = ["=== WebView Security Analysis ==="], []
    seen = set()
    emitted = set()

    def _emit(rule, evidence):
        if (rule, evidence[:30]) not in emitted:
            emitted.add((rule, evidence[:30]))
            F.append({"rule_id": rule, "evidence": evidence})

    patterns = {
        "WEBVIEW_JS_BRIDGE": re.compile(r"addJavascriptInterface"),
        "WEBVIEW_FILE_ACCESS": re.compile(r"setAllowFileAccess\(true\)|setAllowFileAccessFromFileURLs\(true\)"),
        "WEBVIEW_UNIVERSAL_ACCESS": re.compile(r"setAllowUniversalAccessFromFileURLs\(true\)"),
        "WEBVIEW_JS_ENABLED": re.compile(r"setJavaScriptEnabled\(true\)"),
    }

    for d in ctx.dex:
        try:
            strings = d.get_strings()
            if not isinstance(strings, (list, tuple)): continue
            for s in strings:
                if not isinstance(s, str) or s in seen: continue
                seen.add(s)
                for rule, pat in patterns.items():
                    if pat.search(s):
                        L.append(f"  [!] {rule}: {s[:100]}")
                        _emit(rule, s[:100])
        except Exception:
            continue

    if not F:
        L.append("  [-] No dangerous WebView configurations detected.")
    
    return {"tool": "webview", "output": "\n".join(L), "findings": F}
