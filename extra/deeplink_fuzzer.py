NS = "{http://schemas.android.com/apk/res/android}"

def run(ctx):
    L, F = ["=== Deep Link Fuzzer ==="], []
    root = ctx.get_manifest_root()
    
    if root is None:
        L.append("  [!] Could not parse Manifest.")
        return {"tool": "deeplink_fuzzer", "output": "\n".join(L), "findings": []}
        
    app = root.find("application")
    if app is not None:
        for c in app:
            if c.tag not in ("activity", "activity-alias", "service", "receiver"):
                continue
            for itf in c.findall("intent-filter"):
                if not hasattr(itf, 'findall'): continue
                cats = [k.get(f"{NS}name") for k in itf.findall("category") if hasattr(k, 'get')]
                if any("BROWSABLE" in str(x) for x in cats):
                    comp_name = c.get(f"{NS}name", "Unknown")
                    L.append(f"  [!] Browsable activity found: {comp_name}")
                    F.append({"rule_id": "DEEPLINK_BROWSABLE", "evidence": comp_name})
                    
    if not F:
        L.append("  [-] No browsable intent filters (deep links) found.")
        
    return {"tool": "deeplink_fuzzer", "output": "\n".join(L), "findings": F}
