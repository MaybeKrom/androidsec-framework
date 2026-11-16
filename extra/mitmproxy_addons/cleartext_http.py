"""Cleartext HTTP Detector — flag plain HTTP (not HTTPS) requests."""

from __future__ import annotations

from typing import Any

try:
    from ._common import emit_finding, flow_from_mitm, parse_url_parts, print_json
except ImportError:  # mitmdump -s
    from _common import emit_finding, flow_from_mitm, parse_url_parts, print_json

ADDON_ID = "cleartext_http"


def analyze_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    method = str(flow.get("method") or "GET")
    url = str(flow.get("url") or "")
    scheme, _host, _path, pretty = parse_url_parts(url)
    if scheme != "http" and not url.lower().startswith("http://"):
        return []
    return [
        emit_finding(
            addon=ADDON_ID,
            rule_id="MITM_CLEARTEXT_HTTP",
            evidence=(
                f"proxy intercepted cleartext {method} {pretty} "
                f"[lab mitmproxy capture]"
            ),
            detail={
                "method": method,
                "url": pretty,
                "scheme": "http",
            },
        )
    ]


class CleartextHttpAddon:
    def response(self, flow) -> None:
        for finding in analyze_flow(flow_from_mitm(flow)):
            print_json(finding)


addons = [CleartextHttpAddon()]
