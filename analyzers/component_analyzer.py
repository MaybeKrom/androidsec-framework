NS = "{http://schemas.android.com/apk/res/android}"

def run(ctx):
    L, F = ["=== Exported Component Analysis ==="], []
    root = ctx.get_manifest_root()
    if root is None:
        L.append("[!] Could not parse Manifest XML.")
        return {"tool": "component", "output": "\n".join(L), "findings": []}

    app = root.find("application")
    if app is None:
        L.append("No <application> tag found.")
        return {"tool": "component", "output": "\n".join(L), "findings": []}

    TYPE_MAP = {
        "activity":       "COMPONENT_ACTIVITY",
        "activity-alias": "COMPONENT_ACTIVITY",
        "service":        "COMPONENT_SERVICE",
        "receiver":       "COMPONENT_RECEIVER",
        "provider":       "COMPONENT_PROVIDER",
    }

    emitted = set()
    for child in app:
        if child.tag not in TYPE_MAP:
            continue

        name = child.get(f"{NS}name", "Unknown")
        exported = child.get(f"{NS}exported")
        has_intent_filter = len(child.findall("intent-filter")) > 0

        # Android defaults: exported=true if intent-filter present (pre-API 31)
        is_exported = (exported == "true") or (exported is None and has_intent_filter)

        if not is_exported:
            continue

        # Detect launcher activity — informational only
        is_launcher = False
        for itf in child.findall("intent-filter"):
            actions = [a.get(f"{NS}name", "") for a in itf.findall("action")]
            cats = [c.get(f"{NS}name", "") for c in itf.findall("category")]
            if ("android.intent.action.MAIN" in actions and
                    "android.intent.category.LAUNCHER" in cats):
                is_launcher = True

        rule = "COMPONENT_LAUNCHER" if is_launcher else TYPE_MAP[child.tag]
        perm = child.get(f"{NS}permission", "none")

        marker = "i" if is_launcher else "!"
        L.append(f"  [{marker}] {child.tag}: {name} "
                 f"(exported={exported}, permission={perm})")

        key = (rule, name)
        if key not in emitted:
            emitted.add(key)
            F.append({"rule_id": rule, "evidence": f"{name} (permission={perm})"})

    if not F:
        L.append("  [-] No exported components found.")
    else:
        L.insert(1, f"Exported components: {len(F)}")

    return {"tool": "component", "output": "\n".join(L), "findings": F}
