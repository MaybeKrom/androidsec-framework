NS = "{http://schemas.android.com/apk/res/android}"

def run(ctx):
    L, F = ["=== Attack Surface Analysis ==="], []
    root = ctx.get_manifest_root()
    if root is None:
        L.append("[!] Could not parse Manifest XML.")
        return {"tool": "attack_surface", "output": "\n".join(L), "findings": []}

    app = root.find("application")
    if app is None:
        L.append("No <application> tag found.")
        return {"tool": "attack_surface", "output": "\n".join(L), "findings": []}

    for c in app:
        if c.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        try:
            for itf in c.findall("intent-filter"):
                if not hasattr(itf, 'findall'): continue
                actions = [a.get(f"{NS}name") for a in itf.findall("action") if hasattr(a, 'get')]
                cats    = [k.get(f"{NS}name") for k in itf.findall("category") if hasattr(k, 'get')]
                browsable = any(x and "BROWSABLE" in x for x in cats)
                
                for d in itf.findall("data"):
                    if not hasattr(d, 'get'): continue
                    scheme = d.get(f"{NS}scheme")
                    host   = d.get(f"{NS}host")
                    if not scheme: continue
                    
                    comp = c.get(f"{NS}name", "Unknown")
                    L.append(f"  [entry] {c.tag}: {comp}")
                    L.append(f"      scheme={scheme} host={host} actions={actions}")
                    
                    if browsable:
                        if host in (None, "", "*"):
                            F.append({"rule_id": "DEEPLINK_WILDCARD_HOST", "evidence": f"{comp} -> {scheme}://{host}"})
                        if scheme == "http":
                            F.append({"rule_id": "DEEPLINK_HTTP", "evidence": f"{comp} -> http://{host}"})
        except Exception:
            continue

    if not L[1:]:
        L.append("  [-] No intent-filters with data found.")
    return {"tool": "attack_surface", "output": "\n".join(L), "findings": F}
