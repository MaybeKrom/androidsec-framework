CATEGORY = {
    "ACCESS_FINE_LOCATION": "PERMISSION_LOCATION",
    "ACCESS_COARSE_LOCATION": "PERMISSION_LOCATION",
    "ACCESS_BACKGROUND_LOCATION": "PERMISSION_LOCATION",
    "READ_EXTERNAL_STORAGE": "PERMISSION_STORAGE",
    "WRITE_EXTERNAL_STORAGE": "PERMISSION_STORAGE",
    "MANAGE_EXTERNAL_STORAGE": "PERMISSION_STORAGE",
    "READ_SMS": "PERMISSION_SMS", "SEND_SMS": "PERMISSION_SMS", "RECEIVE_SMS": "PERMISSION_SMS",
    "READ_CONTACTS": "PERMISSION_CONTACTS", "WRITE_CONTACTS": "PERMISSION_CONTACTS",
    "CAMERA": "PERMISSION_CAMERA",
    "RECORD_AUDIO": "PERMISSION_MIC",
    "READ_PHONE_STATE": "PERMISSION_PHONE", "READ_PHONE_NUMBERS": "PERMISSION_PHONE",
    "CALL_PHONE": "PERMISSION_PHONE", "READ_CALL_LOG": "PERMISSION_PHONE",
    "SYSTEM_ALERT_WINDOW": "PERMISSION_SYSTEM",
    "REQUEST_INSTALL_PACKAGES": "PERMISSION_SYSTEM",
    "QUERY_ALL_PACKAGES": "PERMISSION_SYSTEM",
    "BODY_SENSORS": "PERMISSION_SENSORS",
    "READ_CALENDAR": "PERMISSION_CALENDAR", "WRITE_CALENDAR": "PERMISSION_CALENDAR",
}

def run(ctx):
    perms = ctx.apk.get_permissions()
    L, F = [f"=== Permission Analysis === ({len(perms)} total)"], []
    dangerous, other = [], []
    for p in perms:
        short = p.split(".")[-1]
        rule = CATEGORY.get(short)
        if rule:
            dangerous.append((p, rule))
            F.append({"rule_id": rule, "evidence": p})
        else:
            other.append(p)
    L.append(f"\nDangerous: {len(dangerous)}")
    for p, _ in dangerous: L.append(f"  [!] {p}")
    L.append(f"\nOther: {len(other)}")
    for p in other: L.append(f"  [+] {p}")
    return {"tool": "permission", "output": "\n".join(L), "findings": F}
