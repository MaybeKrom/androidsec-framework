import re
import urllib.request

FIREBASE_PAT = re.compile(r"https://[a-zA-Z0-9.\-_]+\.firebaseio\.com")

def run(ctx):
    L, F = ["=== Cloud Misconfiguration Checker ==="], []
    urls = set()

    for d in ctx.dex:
        try:
            strings = d.get_strings()
            if not isinstance(strings, (list, tuple)): continue
            for s in strings:
                if not isinstance(s, str): continue
                for m in FIREBASE_PAT.finditer(s):
                    urls.add(m.group(0))
        except Exception:
            continue

    if not urls:
        L.append("  [-] No Firebase URLs found.")
        return {"tool": "cloud_checker", "output": "\n".join(L), "findings": []}

    L.append(f"  [+] Found {len(urls)} Firebase URL(s). Testing read access...")
    for u in urls:
        test_url = u + "/.json"
        try:
            req = urllib.request.Request(test_url, headers={'User-Agent': 'androidsec'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    L.append(f"  [!] PUBLICLY READABLE: {test_url}")
                    F.append({"rule_id": "CLOUD_FIREBASE_OPEN", "evidence": u})
                else:
                    L.append(f"  [-] Secured ({resp.status}): {u}")
        except Exception as e:
            L.append(f"  [-] Blocked/Error: {u}")
            
    return {"tool": "cloud_checker", "output": "\n".join(L), "findings": F}
