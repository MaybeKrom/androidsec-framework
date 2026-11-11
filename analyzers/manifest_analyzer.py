NS = "{http://schemas.android.com/apk/res/android}"

def run(ctx):
    apk = ctx.apk
    L, F = ["=== Manifest Analysis ==="], []
    root = ctx.get_manifest_root()
    if root is None:
        return {"tool": "manifest", "output": "Could not parse manifest", "findings": []}
    app = root.find("application")
    if app is None:
        return {"tool": "manifest", "output": "No <application>", "findings": []}

    debuggable   = app.get(f"{NS}debuggable", "false")
    allow_backup = app.get(f"{NS}allowBackup", "true")
    cleartext    = app.get(f"{NS}usesCleartextTraffic", "not_set")
    net_cfg      = app.get(f"{NS}networkSecurityConfig", "not_set")
    legacy       = app.get(f"{NS}requestLegacyExternalStorage", "false")

    L += [f"debuggable:              {debuggable}",
          f"allowBackup:             {allow_backup}",
          f"usesCleartextTraffic:    {cleartext}",
          f"networkSecurityConfig:   {net_cfg}",
          f"requestLegacyExternalStorage: {legacy}"]

    if debuggable.lower() == "true":
        F.append({"rule_id": "MANIFEST_DEBUGGABLE", "evidence": "debuggable=true"})
    if allow_backup.lower() == "true":
        F.append({"rule_id": "MANIFEST_BACKUP", "evidence": "allowBackup=true (default)"})
    if cleartext.lower() == "true":
        F.append({"rule_id": "MANIFEST_CLEARTEXT", "evidence": "usesCleartextTraffic=true"})
    if legacy.lower() == "true":
        F.append({"rule_id": "MANIFEST_LEGACY_STORAGE", "evidence": "requestLegacyExternalStorage=true"})

    sdk = root.find("uses-sdk")
    if sdk is not None:
        target = sdk.get(f"{NS}targetSdkVersion")
        L.append(f"targetSdkVersion:        {target}")
        try:
            if target and int(target) < 31:
                F.append({"rule_id": "MANIFEST_LOW_TARGET_SDK",
                          "evidence": f"targetSdkVersion={target}"})
        except ValueError:
            pass
    return {"tool": "manifest", "output": "\n".join(L), "findings": F}
