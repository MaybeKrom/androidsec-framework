NS = "{http://schemas.android.com/apk/res/android}"
BLOCKLIST = (
    "schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org",
    "example.com", "schema.org", "google.com", "google-analytics.com",
    "plus.google.com", "goo.gl", "doubleclick.net", "gstatic.com",
    "login.live.com", "login.yahoo.com", "hostname", "localhost"
)

from analyzers.dex_scan import const_strings, iter_app_methods, pretty_class
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
                    # example.com. (trailing dot) is a real host-confusion URL,
                    # not the documentation placeholder example.com.
                    blocked = any(b in s for b in BLOCKLIST)
                    if blocked and "example.com." in s:
                        blocked = False
                    if not blocked and len(s) > 10:
                        http_urls.add(s)
        except Exception:
            continue

    for u in sorted(http_urls)[:15]:
        L.append(f"  [!] HTTP: {u}")
        F.append({"rule_id": "NETWORK_HTTP_URL", "evidence": u})

    # The "http://" prefix and the HttpPost call are often in different methods
    # (a field initializer versus an inner-class request). Match them across
    # the app package. Full http:// URLs are already collected above.
    scheme_sites = []
    client_sites = []
    for class_name, method_name, insns in iter_app_methods(ctx):
        literals = const_strings(insns)
        where = f"{pretty_class(class_name)}->{method_name}"
        if "http://" in literals or any(item.startswith("http://") for item in literals):
            scheme_sites.append(where)
        invokes = "\n".join(output for op, output in insns if "invoke" in op)
        if any(token in invokes for token in ("HttpPost", "HttpGet", "HttpURLConnection", "DefaultHttpClient")):
            client_sites.append(where)
    if scheme_sites and client_sites:
        evidence = (
            f"cleartext http:// in {scheme_sites[0]} "
            f"with HTTP client {client_sites[0]}"
        )
        L.append(f"  [!] HTTP client: {evidence}")
        F.append({"rule_id": "NETWORK_HTTP_URL", "evidence": evidence})

    return {"tool": "network", "output": "\n".join(L), "findings": F}
