NS = "{http://schemas.android.com/apk/res/android}"
BLOCKLIST = (
    "schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org",
    "example.com", "schema.org", "google.com", "google-analytics.com",
    "plus.google.com", "goo.gl", "doubleclick.net", "gstatic.com",
    "login.live.com", "login.yahoo.com", "hostname", "localhost"
)

from analyzers.utils import has_network_capability as _has_network_capability


def run(ctx):
    L, F = ["=== Network Configuration Analysis ==="], []
    
    net_cfg = cleartext = None
    root = ctx.get_manifest_root()
    
    if root is not None:
        app = root.find("application")
        if app is not None:
            net_cfg   = app.get(f"{NS}networkSecurityConfig")
            cleartext = app.get(f"{NS}usesCleartextTraffic")

    L.append(f"networkSecurityConfig: {net_cfg or 'NOT DEFINED'}")
    L.append(f"usesCleartextTraffic:  {cleartext or 'not_set'}")

    has_net, why = _has_network_capability(ctx)
    L.append(f"Network capability:    {'YES' if has_net else 'NO'} ({why})")

    if not net_cfg and has_net:
        F.append({"rule_id": "NETWORK_NO_CONFIG", "evidence": f"no networkSecurityConfig ({why})"})
    
    if (cleartext or "").lower() == "true":
        F.append({"rule_id": "NETWORK_CLEARTEXT_ALLOWED", "evidence": "usesCleartextTraffic=true"})

    http_urls = set()
    for d in ctx.dex:
        try:
            strings = d.get_strings()
            if not isinstance(strings, (list, tuple)): continue
            for s in strings:
                if not isinstance(s, str): continue
                if s.startswith("http://"):
                    if not any(b in s for b in BLOCKLIST) and len(s) > 10:
                        http_urls.add(s)
        except Exception:
            continue

    for u in sorted(http_urls)[:15]:
        L.append(f"  [!] HTTP: {u}")
        F.append({"rule_id": "NETWORK_HTTP_URL", "evidence": u})

    return {"tool": "network", "output": "\n".join(L), "findings": F}
