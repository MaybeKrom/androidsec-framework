import re

URL_PAT = re.compile(r"https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>]*)?")
S3_PAT = re.compile(r"[a-zA-Z0-9.\-_]+\.s3(?:[.-][a-z0-9]+)?\.amazonaws\.com")

def run(ctx):
    L, F = ["=== API & Endpoint Recon ==="], []
    urls, s3s = set(), set()

    for d in ctx.dex:
        try:
            strings = d.get_strings()
            if not isinstance(strings, (list, tuple)): continue
            for s in strings:
                if not isinstance(s, str): continue
                for m in URL_PAT.finditer(s):
                    if "schemas.android.com" not in m.group(0):
                        urls.add(m.group(0))
                for m in S3_PAT.finditer(s):
                    s3s.add(m.group(0))
        except Exception:
            continue

    L.append(f"  [-] Extracted {len(urls)} URLs and {len(s3s)} S3 Buckets.")
    
    if urls:
        L.append("\n  [+] Potential API Endpoints:")
        for u in sorted(urls)[:30]: # Cap at 30 for readability
            L.append(f"      {u}")
            
    if s3s:
        L.append("\n  [+] AWS S3 Buckets:")
        for s in sorted(s3s):
            L.append(f"      {s}")
            F.append({"rule_id": "CLOUD_S3_BUCKET_FOUND", "evidence": s})

    return {"tool": "api_extractor", "output": "\n".join(L), "findings": F}
