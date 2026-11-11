import os

from analyzers.utils import fmt_size as _fmt_size

def run(ctx):
    apk = ctx.apk
    L, F = ["=== APK Information ==="], []
    L.append(f"File:          {os.path.basename(ctx.apk_path)}")
    L.append(f"Size:          {_fmt_size(os.path.getsize(ctx.apk_path))}")
    
    try:
        safe_app_name = apk.get_app_name()
    except Exception:
        safe_app_name = apk.get_package()
    L.append(f"App name:      {safe_app_name}")

    L.append(f"Package:       {apk.get_package()}")
    L.append(f"Version name:  {apk.get_androidversion_name()}")
    
    try:
        vcode = apk.get_androidversion_code()
    except Exception:
        vcode = "?"
    L.append(f"Version code:  {vcode if vcode not in (None, '') else '?'}")
    
    try:
        safe_min_sdk = apk.get_min_sdk_version()
    except Exception:
        safe_min_sdk = "Unknown"
        
    try:
        safe_target_sdk = apk.get_target_sdk_version()
    except Exception:
        safe_target_sdk = "Unknown"

    L.append(f"Min SDK:       {safe_min_sdk}")
    L.append(f"Target SDK:    {safe_target_sdk}")
    L.append(f"Main activity: {apk.get_main_activity()}")
    L.append(f"Signed:        {apk.is_signed()}")

    try:
        certs = apk.get_certificates()
    except Exception:
        certs = []

    L.append(f"\nCertificates: {len(certs)}")
    for i, c in enumerate(certs, 1):
        L.append(f"  [{i}] Subject: {c.subject.human_friendly}")
        L.append(f"      Issuer:  {c.issuer.human_friendly}")
        L.append(f"      Serial:  {c.serial_number}")
        L.append(f"      SHA1:    {c.sha1_fingerprint}")
        L.append(f"      SHA256:  {c.sha256_fingerprint}")
        try:
            from datetime import datetime
            if c.not_valid_after < datetime.now():
                F.append({"rule_id": "CERT_EXPIRED",
                          "evidence": f"Cert {i} expired {c.not_valid_after}"})
                L.append(f"      [!] EXPIRED {c.not_valid_after}")
        except Exception:
            pass

    return {"tool": "apk_info", "output": "\n".join(L), "findings": F}
