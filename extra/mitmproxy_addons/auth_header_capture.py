"""Authorization Header Capture — extract Authorization and Cookie when present."""

from __future__ import annotations

from typing import Any

try:
    from ._common import clip, emit_finding, flow_from_mitm, parse_url_parts, print_json
except ImportError:  # mitmdump -s
    from _common import clip, emit_finding, flow_from_mitm, parse_url_parts, print_json

ADDON_ID = "auth_header_capture"
_TARGET_HEADERS = ("authorization", "cookie")


def analyze_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    method = str(flow.get("method") or "GET")
    url = str(flow.get("url") or "")
    _scheme, _host, _path, pretty = parse_url_parts(url)
    headers = flow.get("headers") or {}
    if not isinstance(headers, dict):
        return findings

    for name, value in headers.items():
        lname = str(name).lower()
        if lname not in _TARGET_HEADERS:
            continue
        clipped = clip(str(value), 80)
        findings.append(
            emit_finding(
                addon=ADDON_ID,
                rule_id="MITM_SENSITIVE_HEADER",
                evidence=(
                    f"proxy intercepted {method} {pretty} "
                    f"header {name}: {clipped} "
                    f"[lab mitmproxy capture]"
                ),
                detail={
                    "method": method,
                    "url": pretty,
                    "header": str(name),
                    "value_clip": clipped,
                },
            )
        )
    return findings


class AuthHeaderCaptureAddon:
    def response(self, flow) -> None:
        for finding in analyze_flow(flow_from_mitm(flow)):
            print_json(finding)


addons = [AuthHeaderCaptureAddon()]
