"""Optional mitmproxy / traffic-dump analyzer for lab dynamic analysis.

Capture modes (first match wins):
1. Offline: parse ``ANDROSEC_MITM_DUMP`` (JSON flow list, HAR, or NDJSON).
2. Live (best-effort): if a device is ready, automatically set the device
   global HTTP proxy via ADB, start ``mitmdump`` with
   ``extra/mitmproxy_addons/loader.py`` when needed, launch the package
   briefly, dump flows under the report/output dir, then always clear the
   proxy in ``finally``.
3. Otherwise skip — never fails the whole scan.

Lab-only: Genymotion / emulator / rooted phone with mitmproxy CA installed
(CA install remains a one-time lab setup; proxy routing is automated).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from urllib.parse import urlparse

from analyzers.utils import device_ready

try:
    from extra.mitmproxy_addons import loader_script_path as _addons_loader_path
except Exception:  # pragma: no cover - package layout fallback
    def _addons_loader_path() -> str:
        return os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "mitmproxy_addons",
            "loader.py",
        )

_SENSITIVE_HEADER = re.compile(
    r"(?i)^(authorization|cookie|x-api-key|x-auth-token|api-key|proxy-authorization)$"
)
_SENSITIVE_BODY = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+"
)
_DEFAULT_PORT = int(os.environ.get("ANDROSEC_MITM_PORT", "8080") or "8080")
_LIVE_SECONDS = int(os.environ.get("ANDROSEC_MITM_SECONDS", "12") or "12")
_PROXY_CLEAR_VALUE = ":0"


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


def _is_addon_record(obj: dict) -> bool:
    kind = obj.get("androsec")
    return kind in ("mitm_finding", "mitm_endpoint", "mitm_report")


def parse_mitm_dump(raw: str) -> list[dict]:
    """Parse HAR, JSON array, single JSON object, or NDJSON into normalized flows.

    Addon JSON lines (``androsec: mitm_*``) are ignored here — use
    ``parse_addon_output``.
    """
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
        if _is_addon_record(data):
            return []
        if "log" in data and "entries" in (data.get("log") or {}):
            return list(_iter_flows_from_har(data))
        if "flows" in data and isinstance(data["flows"], list):
            for item in data["flows"]:
                if isinstance(item, dict) and _is_addon_record(item):
                    continue
                norm = _normalize_flow(item)
                if norm:
                    flows.append(norm)
            return flows
        norm = _normalize_flow(data)
        return [norm] if norm else []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and _is_addon_record(item):
                continue
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
        if isinstance(obj, dict) and _is_addon_record(obj):
            continue
        norm = _normalize_flow(obj)
        if norm:
            flows.append(norm)
    return flows


def parse_addon_output(raw: str) -> tuple[list[dict], list[str], list[dict]]:
    """Parse addon NDJSON into findings, report lines, and endpoint records.

    Returns ``(findings, report_lines, endpoints)`` where findings are
    ``{rule_id, evidence}`` rows for the existing MITM_* pipeline.
    """
    findings: list[dict] = []
    reports: list[str] = []
    endpoints: list[dict] = []
    seen: set[str] = set()

    text = (raw or "").strip()
    if not text:
        return findings, reports, endpoints

    def _consume(obj: dict) -> None:
        kind = obj.get("androsec")
        if kind == "mitm_finding":
            rule_id = str(obj.get("rule_id") or "").strip()
            evidence = str(obj.get("evidence") or "").strip()
            if not rule_id or not evidence:
                return
            key = f"{rule_id}:{evidence}"
            if key in seen:
                return
            seen.add(key)
            findings.append({"rule_id": rule_id, "evidence": evidence})
        elif kind == "mitm_endpoint":
            endpoints.append(obj)
        elif kind == "mitm_report":
            report = str(obj.get("report") or "").strip()
            if report:
                reports.append(report)

    # Full JSON document
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        _consume(data)
        return findings, reports, endpoints
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _consume(item)
        return findings, reports, endpoints

    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            _consume(obj)
    return findings, reports, endpoints


def merge_mitm_findings(*groups: list[dict]) -> list[dict]:
    """Dedupe finding dicts by rule_id + evidence."""
    merged: list[dict] = []
    seen: set[str] = set()
    for group in groups:
        for item in group or []:
            rule_id = str(item.get("rule_id") or "")
            evidence = str(item.get("evidence") or "")
            key = f"{rule_id}:{evidence}"
            if not rule_id or key in seen:
                continue
            seen.add(key)
            merged.append({"rule_id": rule_id, "evidence": evidence})
    return merged


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


def _adb_cmd(*args: str, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["adb", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _adb_getprop(prop: str) -> str:
    try:
        result = _adb_cmd("shell", "getprop", prop, timeout=5)
        return (result.stdout or "").strip()
    except Exception:
        return ""


def _device_fingerprint_blob() -> str:
    """Collect cheap device identity strings for proxy-host heuristics."""
    parts = [
        (os.environ.get("ANDROSEC_DEVICE_HINT") or "").lower(),
        _adb_getprop("ro.product.manufacturer").lower(),
        _adb_getprop("ro.product.model").lower(),
        _adb_getprop("ro.product.brand").lower(),
        _adb_getprop("ro.hardware").lower(),
        _adb_getprop("ro.product.device").lower(),
        _adb_getprop("ro.build.fingerprint").lower(),
        _adb_getprop("ro.boot.hardware").lower(),
    ]
    return " ".join(p for p in parts if p)


def resolve_proxy_host() -> tuple[str, str]:
    """Pick the HTTP proxy host as seen from the Android lab device.

    Returns ``(host, reason)``.
    Priority: ``ANDROSEC_MITM_HOST`` → Genymotion hint/props → AVD/emulator →
    default AVD alias ``10.0.2.2``.
    """
    override = (os.environ.get("ANDROSEC_MITM_HOST") or "").strip()
    if override:
        return override, "ANDROSEC_MITM_HOST"

    hint = (os.environ.get("ANDROSEC_DEVICE_HINT") or "").lower()
    geny_host = (os.environ.get("ANDROSEC_GENYMOTION_HOST") or "10.0.3.2").strip() or "10.0.3.2"

    if "genymotion" in hint or "geny" in hint:
        return geny_host, "ANDROSEC_DEVICE_HINT=genymotion"

    blob = _device_fingerprint_blob()
    qemu = _adb_getprop("ro.kernel.qemu")

    if any(
        token in blob
        for token in ("genymotion", "genymobile", "vbox86", "vbox86p", "ttvm")
    ):
        return geny_host, "detected Genymotion/VirtualBox guest"

    if (
        qemu == "1"
        or any(token in blob for token in ("goldfish", "ranchu", "sdk_gphone", "emulator", "google_sdk"))
    ):
        return "10.0.2.2", "detected Android Emulator (AVD)"

    # Unknown physical / custom image: AVD alias is still the safest default for
    # lab docs; operators override with ANDROSEC_MITM_HOST.
    return "10.0.2.2", "default AVD host alias (set ANDROSEC_MITM_HOST to override)"


def _emulator_proxy_host() -> str:
    """Back-compat wrapper used by older call sites / tests."""
    host, _reason = resolve_proxy_host()
    return host


def _port_is_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def set_device_http_proxy(host: str, port: int) -> tuple[bool, str]:
    """Set Android global HTTP proxy via ADB (``settings put global http_proxy``)."""
    target = f"{host}:{port}"
    try:
        result = _adb_cmd(
            "shell", "settings", "put", "global", "http_proxy", target, timeout=10
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "adb settings put failed").strip()
            return False, err[:200]
        return True, target
    except Exception as exc:
        return False, str(exc)


def clear_device_http_proxy() -> tuple[bool, str]:
    """Clear Android global HTTP proxy (``:0`` — works where ``settings delete`` does not)."""
    try:
        result = _adb_cmd(
            "shell",
            "settings",
            "put",
            "global",
            "http_proxy",
            _PROXY_CLEAR_VALUE,
            timeout=10,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "adb clear proxy failed").strip()
            return False, err[:200]
        return True, _PROXY_CLEAR_VALUE
    except Exception as exc:
        return False, str(exc)


def _set_device_proxy(host: str, port: int) -> tuple[bool, str]:
    return set_device_http_proxy(host, port)


def _clear_device_proxy() -> None:
    clear_device_http_proxy()


def resolve_dump_dir() -> str:
    """Directory for live flow dumps (report/output dir preferred)."""
    for key in ("ANDROSEC_MITM_OUT", "ANDROSEC_OUTPUT_DIR"):
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "output_reports")


def resolve_addon_loader() -> str | None:
    """Return path to ``mitmproxy_addons/loader.py`` when present."""
    path = _addons_loader_path()
    return path if path and os.path.isfile(path) else None


def _live_capture(package: str, dump_path: str) -> tuple[bool, str]:
    """Best-effort mitmdump capture with automatic device proxy set/clear.

    Starts ``mitmdump -s extra/mitmproxy_addons/loader.py`` so practical addons
    (sensitive data, cleartext HTTP, API endpoints, auth headers) emit JSON
    findings alongside the flow dump. Always clears ``global http_proxy`` in
    ``finally``. Failures return ``(False, message)`` — callers skip network
    capture without failing the whole scan.
    """
    mitmdump = shutil.which("mitmdump")
    port = _DEFAULT_PORT
    host, host_reason = resolve_proxy_host()
    started_mitmdump = False
    proc = None
    out_f = None
    addon_path = resolve_addon_loader()

    try:
        reuse_existing = _port_is_listening(port)
        if not reuse_existing:
            if not mitmdump:
                return False, "mitmdump not on PATH and nothing listening on proxy port"
            if not addon_path:
                return False, "mitmproxy addon loader missing (extra/mitmproxy_addons/loader.py)"

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
            started_mitmdump = True
            time.sleep(1.5)
            if proc.poll() is not None:
                return False, f"mitmdump exited early (port {port})"
        else:
            # Existing listener (operator-started mitmdump). Still set device proxy;
            # dump file may stay empty unless that process writes here.
            if not os.path.exists(dump_path):
                open(dump_path, "a", encoding="utf-8").close()

        ok, msg = set_device_http_proxy(host, port)
        if not ok:
            return False, f"could not set device proxy via ADB: {msg}"

        if package:
            try:
                _adb_cmd(
                    "shell",
                    "monkey",
                    "-p",
                    package,
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "1",
                    timeout=15,
                )
            except Exception:
                pass

        time.sleep(max(3, _LIVE_SECONDS))
        mode = "reused listener" if reuse_existing else f"started mitmdump -s {os.path.basename(addon_path or 'loader.py')}"
        return True, (
            f"live capture → {dump_path} (proxy {host}:{port}; {host_reason}; {mode})"
        )
    except Exception as exc:
        return False, f"live capture failed: {exc}"
    finally:
        # Always clear — even when set failed mid-flight or capture errored.
        try:
            clear_device_http_proxy()
        except Exception:
            pass
        if started_mitmdump and proc is not None:
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
        port = _DEFAULT_PORT
        if not ok:
            lines.append(
                f"[!] {reason} — SKIPPED network capture "
                "(set ANDROSEC_MITM_DUMP for offline analysis)"
            )
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

        listener_up = _port_is_listening(port)
        if not mitmdump and not listener_up and not dump_env:
            lines.append(
                "[!] mitmdump not on PATH, nothing listening on "
                f"port {port}, and no ANDROSEC_MITM_DUMP — SKIPPED. "
                "Install mitmproxy (CA install is a one-time lab step for HTTPS)."
            )
            findings.append({
                "rule_id": "MITM_PROXY_NOT_READY",
                "evidence": "mitmdump missing; no offline dump; proxy port closed",
            })
            return {
                "tool": "mitmproxy",
                "output": "\n".join(lines),
                "findings": findings,
                "skipped": True,
            }

        if mitmdump or listener_up:
            try:
                package = ctx.apk.get_package()
            except Exception:
                package = ""
            out_dir = resolve_dump_dir()
            try:
                os.makedirs(out_dir, exist_ok=True)
            except Exception as exc:
                lines.append(f"[!] Cannot create dump dir {out_dir}: {exc} — SKIPPED")
                findings.append({
                    "rule_id": "MITM_PROXY_NOT_READY",
                    "evidence": f"dump dir error: {exc}",
                })
                return {
                    "tool": "mitmproxy",
                    "output": "\n".join(lines),
                    "findings": findings,
                    "skipped": True,
                }
            dump_path = os.path.join(out_dir, "androsec_mitm_flows.ndjson")
            host, host_reason = resolve_proxy_host()
            lines.append(
                f"[*] Auto device proxy: will set global http_proxy → {host}:{port} "
                f"({host_reason}), then clear to {_PROXY_CLEAR_VALUE}"
            )
            live_ok, live_msg = _live_capture(package or "", dump_path)
            lines.append(f"[*] Live capture: {live_msg}")
            if live_ok and os.path.isfile(dump_path):
                dump_text = _load_dump_text(dump_path)
                source = "live mitmdump (auto proxy)"
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
    addon_findings, addon_reports, addon_endpoints = parse_addon_output(dump_text)

    lines.extend(detail_lines)
    for report in addon_reports:
        lines.append(report)
    if addon_endpoints and not addon_reports:
        # Offline / mixed dumps may contain endpoint records without a report block.
        try:
            from extra.mitmproxy_addons.api_endpoint_logger import format_endpoint_report

            lines.append(format_endpoint_report(addon_endpoints))
        except Exception:
            lines.append(f"[i] Unique endpoints from addons: {len(addon_endpoints)}")

    # Prefer union of flow analysis + addon JSON (deduped). Offline dumps without
    # addon lines still work via analyze_flows alone.
    findings.extend(merge_mitm_findings(flow_findings, addon_findings))

    # If both paths only produced traffic summaries, keep a single summary.
    summaries = [f for f in findings if f.get("rule_id") == "MITM_TRAFFIC_SUMMARY"]
    others = [f for f in findings if f.get("rule_id") != "MITM_TRAFFIC_SUMMARY"]
    if others and summaries:
        findings = others
    elif len(summaries) > 1:
        findings = others + summaries[:1]

    loader = resolve_addon_loader()
    if loader and "live" in source:
        lines.append(f"[*] Addons: mitmdump -s {loader}")
    if source:
        lines.append(f"[*] Source: {source}")

    lines.append(
        "[i] Lab setup: install mitmproxy CA as user CA once for HTTPS. "
        "Device HTTP proxy is set/cleared automatically via ADB when this "
        "analyzer is enabled (AVD 10.0.2.2 / Genymotion host bridge / "
        "ANDROSEC_MITM_HOST). Prefer Genymotion/official emulator/rooted phone."
    )

    return {"tool": "mitmproxy", "output": "\n".join(lines), "findings": findings}
