"""Optional mitmproxy / traffic-dump analyzer for lab dynamic analysis.

Capture modes (first match wins):
1. Offline: parse ``ANDROSEC_MITM_DUMP`` (JSON flow list, HAR, or NDJSON).
2. Live (best-effort): if ``mitmdump`` is on PATH and a device is ready, briefly
   set the device HTTP proxy, launch the package, dump flows, then clear proxy.
3. Otherwise skip — never fails the whole scan.

Lab-only: Genymotion / emulator / rooted phone with mitmproxy CA installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlparse

from analyzers.utils import device_ready

_SENSITIVE_HEADER = re.compile(
    r"(?i)^(authorization|cookie|x-api-key|x-auth-token|api-key|proxy-authorization)$"
)
_SENSITIVE_BODY = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+"
)
_DEFAULT_PORT = int(os.environ.get("ANDROSEC_MITM_PORT", "8080") or "8080")
_LIVE_SECONDS = int(os.environ.get("ANDROSEC_MITM_SECONDS", "12") or "12")


def _clip(text: str, n: int = 220) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def _host_path(url: str) -> str:
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        return f"{parsed.scheme or 'http'}://{parsed.netloc}{path}"
    except Exception:
        return url[:160]


def _iter_flows_from_har(data: dict):
    entries = (data.get("log") or {}).get("entries") or []
    for entry in entries:
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        headers = {
            str(h.get("name") or ""): str(h.get("value") or "")
            for h in (req.get("headers") or [])
            if isinstance(h, dict)
        }
        body = ""
        post = req.get("postData") or {}
        if isinstance(post, dict):
            body = str(post.get("text") or "")
        yield {
            "method": str(req.get("method") or "GET"),
            "url": str(req.get("url") or ""),
            "headers": headers,
            "request_body": body,
            "status": resp.get("status"),
            "response_body": str(((resp.get("content") or {}).get("text")) or ""),
        }


def _normalize_flow(obj: dict) -> dict | None:
    if not isinstance(obj, dict):
        return None
    # mitmproxy JSON export style
    if "request" in obj and isinstance(obj["request"], dict):
        req = obj["request"]
        resp = obj.get("response") if isinstance(obj.get("response"), dict) else {}
        headers = {}
        raw_headers = req.get("headers") or []
        if isinstance(raw_headers, dict):
            headers = {str(k): str(v) for k, v in raw_headers.items()}
        elif isinstance(raw_headers, list):
            for item in raw_headers:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    headers[str(item[0])] = str(item[1])
                elif isinstance(item, dict):
                    headers[str(item.get("name") or item.get("key") or "")] = str(
                        item.get("value") or ""
                    )
        url = str(req.get("url") or req.get("pretty_url") or "")
        if not url:
            host = req.get("host") or req.get("pretty_host")
            path = req.get("path") or "/"
            scheme = req.get("scheme") or "http"
            if host:
                url = f"{scheme}://{host}{path}"
        body = req.get("content") or req.get("text") or req.get("body") or ""
        if isinstance(body, (bytes, bytearray)):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                body = str(body)
        return {
            "method": str(req.get("method") or "GET"),
            "url": url,
            "headers": headers,
            "request_body": str(body or ""),
            "status": (resp or {}).get("status_code") or (resp or {}).get("status"),
            "response_body": str(
                (resp or {}).get("content")
                or (resp or {}).get("text")
                or (resp or {}).get("body")
                or ""
            ),
        }
    # Flat fixture style
    if obj.get("url") or obj.get("path"):
        headers = obj.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        return {
            "method": str(obj.get("method") or "GET"),
            "url": str(obj.get("url") or obj.get("path") or ""),
            "headers": {str(k): str(v) for k, v in headers.items()},
            "request_body": str(obj.get("request_body") or obj.get("body") or ""),
            "status": obj.get("status"),
            "response_body": str(obj.get("response_body") or ""),
        }
    return None


def parse_mitm_dump(raw: str) -> list[dict]:
    """Parse HAR, JSON array, single JSON object, or NDJSON into normalized flows."""
    text = (raw or "").strip()
    if not text:
        return []

    flows: list[dict] = []

    # Try full JSON first.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        if "log" in data and "entries" in (data.get("log") or {}):
            return list(_iter_flows_from_har(data))
        if "flows" in data and isinstance(data["flows"], list):
            for item in data["flows"]:
                norm = _normalize_flow(item)
                if norm:
                    flows.append(norm)
            return flows
        norm = _normalize_flow(data)
        return [norm] if norm else []

    if isinstance(data, list):
        for item in data:
            norm = _normalize_flow(item)
            if norm:
                flows.append(norm)
        return flows

    # NDJSON / one JSON object per line
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        norm = _normalize_flow(obj)
        if norm:
            flows.append(norm)
    return flows


def analyze_flows(flows: list[dict]) -> tuple[list[str], list[dict]]:
    """Turn normalized flows into report lines + findings."""
    lines: list[str] = []
    findings: list[dict] = []
    if not flows:
        lines.append("[-] No HTTP(S) flows in dump.")
        return lines, findings

    lines.append(f"Flows analyzed: {len(flows)}")
    hosts: list[str] = []
    seen_rules: set[str] = set()

    for flow in flows[:200]:
        method = flow.get("method") or "GET"
        url = flow.get("url") or ""
        hp = _host_path(url)
        if hp and hp not in hosts:
            hosts.append(hp)
        lines.append(f"  {method} {hp}")

        if url.lower().startswith("http://"):
            key = f"MITM_CLEARTEXT_HTTP:{hp}"
            if key not in seen_rules:
                seen_rules.add(key)
                findings.append({
                    "rule_id": "MITM_CLEARTEXT_HTTP",
                    "evidence": (
                        f"proxy intercepted cleartext {method} {hp} "
                        f"[lab mitmproxy capture]"
                    ),
                })

        headers = flow.get("headers") or {}
        for name, value in headers.items():
            if _SENSITIVE_HEADER.match(str(name) or ""):
                ev = (
                    f"proxy intercepted {method} {hp} "
                    f"header {name}: {_clip(str(value), 80)} "
                    f"[lab mitmproxy capture]"
                )
                findings.append({
                    "rule_id": "MITM_SENSITIVE_HEADER",
                    "evidence": ev,
                })
                lines.append(f"  [!] sensitive header {name} on {hp}")
                break

        body = str(flow.get("request_body") or "")
        resp = str(flow.get("response_body") or "")
        for blob in (body, resp):
            match = _SENSITIVE_BODY.search(blob)
            if match:
                findings.append({
                    "rule_id": "MITM_SENSITIVE_BODY",
                    "evidence": (
                        f"proxy intercepted {method} {hp} "
                        f"body {_clip(match.group(0), 100)} "
                        f"[lab mitmproxy capture]"
                    ),
                })
                lines.append(f"  [!] sensitive body pattern on {hp}")
                break

    if findings:
        lines.append(f"[+] Sensitive / cleartext hits: {len(findings)}")
    else:
        summary = "; ".join(hosts[:8]) or "(no hosts)"
        findings.append({
            "rule_id": "MITM_TRAFFIC_SUMMARY",
            "evidence": f"proxy intercepted {len(flows)} flow(s): {summary}",
        })
        lines.append("[i] Traffic captured; no sensitive header/body patterns matched.")

    return lines, findings


def _load_dump_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _emulator_proxy_host() -> str:
    """Best-effort host IP as seen from the Android emulator/device."""
    override = (os.environ.get("ANDROSEC_MITM_HOST") or "").strip()
    if override:
        return override
    # Common defaults: AVD → 10.0.2.2; Genymotion often uses the host bridge.
    hint = (os.environ.get("ANDROSEC_DEVICE_HINT") or "").lower()
    if "genymotion" in hint:
        return os.environ.get("ANDROSEC_GENYMOTION_HOST", "10.0.3.2")
    return "10.0.2.2"


def _set_device_proxy(host: str, port: int) -> tuple[bool, str]:
    try:
        # global http proxy (works on many emulators; ignored safely if unsupported)
        r1 = subprocess.run(
            ["adb", "shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"],
            capture_output=True, text=True, timeout=10,
        )
        return r1.returncode == 0, (r1.stderr or r1.stdout or "")[:200]
    except Exception as exc:
        return False, str(exc)


def _clear_device_proxy() -> None:
    try:
        subprocess.run(
            ["adb", "shell", "settings", "put", "global", "http_proxy", ":0"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        pass


def _live_capture(package: str, dump_path: str) -> tuple[bool, str]:
    """Best-effort mitmdump capture. Returns (ok, message)."""
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        return False, "mitmdump not on PATH"

    host = _emulator_proxy_host()
    port = _DEFAULT_PORT
    # Write flows as JSON lines via a tiny addon inline is heavy; use
    # --set harddump + flow export. Prefer saving stream file then reading
    # with a simple request-log addon through -w (binary). For portability we
    # ask mitmdump to write a dumper script that prints JSON lines.
    addon = r"""
from mitmproxy import http
import json

def response(flow: http.HTTPFlow):
    req = flow.request
    headers = [[k, v] for k, v in req.headers.items(multi=True)]
    obj = {
        "request": {
            "method": req.method,
            "url": req.pretty_url,
            "headers": headers,
            "content": req.get_text(strict=False) or "",
        },
        "response": {
            "status_code": flow.response.status_code if flow.response else None,
            "text": (flow.response.get_text(strict=False) if flow.response else "") or "",
        },
    }
    print(json.dumps(obj), flush=True)
"""
    with tempfile.NamedTemporaryFile("w", suffix="_androsec_mitm.py", delete=False) as handle:
        handle.write(addon)
        addon_path = handle.name

    proc = None
    out_f = None
    try:
        out_f = open(dump_path, "w", encoding="utf-8")
        proc = subprocess.Popen(
            [
                mitmdump,
                "-p", str(port),
                "-s", addon_path,
                "--set", "block_global=false",
                "--quiet",
            ],
            stdout=out_f,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        ok, msg = _set_device_proxy(host, port)
        if not ok:
            return False, f"could not set device proxy: {msg}"

        if package:
            subprocess.run(
                [
                    "adb", "shell", "monkey", "-p", package,
                    "-c", "android.intent.category.LAUNCHER", "1",
                ],
                capture_output=True, timeout=15,
            )
        time.sleep(max(3, _LIVE_SECONDS))
        return True, f"live capture → {dump_path} (proxy {host}:{port})"
    except Exception as exc:
        return False, f"live capture failed: {exc}"
    finally:
        _clear_device_proxy()
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if out_f is not None:
            try:
                out_f.close()
            except Exception:
                pass
        try:
            os.remove(addon_path)
        except OSError:
            pass


def run(ctx):
    lines = ["=== mitmproxy Network Analyzer (lab) ==="]
    findings: list[dict] = []

    dump_env = (os.environ.get("ANDROSEC_MITM_DUMP") or "").strip()
    dump_text = ""
    source = ""

    if dump_env and os.path.isfile(dump_env):
        try:
            dump_text = _load_dump_text(dump_env)
            source = f"offline dump {dump_env}"
            lines.append(f"[*] Using offline dump: {dump_env}")
        except Exception as exc:
            lines.append(f"[!] Failed to read ANDROSEC_MITM_DUMP: {exc}")

    if not dump_text:
        ok, reason = device_ready()
        mitmdump = shutil.which("mitmdump")
        if not ok:
            lines.append(f"[!] {reason} — SKIPPED (set ANDROSEC_MITM_DUMP for offline analysis)")
            findings.append({
                "rule_id": "MITM_PROXY_NOT_READY",
                "evidence": reason,
            })
            return {
                "tool": "mitmproxy",
                "output": "\n".join(lines),
                "findings": findings,
                "skipped": True,
            }
        if not mitmdump and not dump_env:
            lines.append(
                "[!] mitmdump not on PATH and no ANDROSEC_MITM_DUMP — SKIPPED. "
                "Install mitmproxy and install the CA on the lab device/emulator."
            )
            findings.append({
                "rule_id": "MITM_PROXY_NOT_READY",
                "evidence": "mitmdump missing; no offline dump",
            })
            return {
                "tool": "mitmproxy",
                "output": "\n".join(lines),
                "findings": findings,
                "skipped": True,
            }

        if mitmdump:
            try:
                package = ctx.apk.get_package()
            except Exception:
                package = ""
            out_dir = os.environ.get("ANDROSEC_MITM_OUT") or tempfile.gettempdir()
            os.makedirs(out_dir, exist_ok=True)
            dump_path = os.path.join(out_dir, "androsec_mitm_flows.ndjson")
            live_ok, live_msg = _live_capture(package or "", dump_path)
            lines.append(f"[*] Live capture: {live_msg}")
            if live_ok and os.path.isfile(dump_path):
                dump_text = _load_dump_text(dump_path)
                source = "live mitmdump"
            else:
                findings.append({
                    "rule_id": "MITM_PROXY_NOT_READY",
                    "evidence": live_msg,
                })
                return {
                    "tool": "mitmproxy",
                    "output": "\n".join(lines),
                    "findings": findings,
                    "skipped": True,
                }

    flows = parse_mitm_dump(dump_text)
    detail_lines, flow_findings = analyze_flows(flows)
    lines.extend(detail_lines)
    findings.extend(flow_findings)
    if source:
        lines.append(f"[*] Source: {source}")

    # Setup reminder for operators (not a finding).
    lines.append(
        "[i] Lab setup: install mitmproxy CA as user CA; point device proxy to "
        "host:8080 (AVD 10.0.2.2 / Genymotion host bridge). "
        "Prefer Genymotion/official emulator/rooted phone."
    )

    return {"tool": "mitmproxy", "output": "\n".join(lines), "findings": findings}
