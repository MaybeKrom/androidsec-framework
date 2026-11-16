"""Sensitive Data Detector — keywords in URLs, headers, and bodies.

Keywords: password, token, secret, api_key, authorization, bearer.
Emits structured ``MITM_SENSITIVE_HEADER`` / ``MITM_SENSITIVE_BODY`` findings.
"""

from __future__ import annotations

from typing import Any

try:
    from ._common import (  # type: ignore[import-not-found]
        clip,
        emit_finding,
        flow_from_mitm,
        keyword_hits,
        parse_url_parts,
        print_json,
    )
except ImportError:  # mitmdump -s (script dir on sys.path)
    from _common import (  # type: ignore[no-redef]
        clip,
        emit_finding,
        flow_from_mitm,
        keyword_hits,
        parse_url_parts,
        print_json,
    )

ADDON_ID = "sensitive_data"


def analyze_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return structured findings for one normalized flow (no mitmproxy needed)."""
    findings: list[dict[str, Any]] = []
    method = str(flow.get("method") or "GET")
    url = str(flow.get("url") or "")
    _scheme, _host, _path, pretty = parse_url_parts(url)

    url_hits = keyword_hits(url)
    if url_hits:
        findings.append(
            emit_finding(
                addon=ADDON_ID,
                rule_id="MITM_SENSITIVE_BODY",
                evidence=(
                    f"proxy intercepted {method} {pretty} "
                    f"url keywords={','.join(url_hits)} "
                    f"[lab mitmproxy capture]"
                ),
                detail={
                    "method": method,
                    "url": pretty,
                    "location": "url",
                    "keywords": url_hits,
                },
            )
        )

    headers = flow.get("headers") or {}
    if isinstance(headers, dict):
        for name, value in headers.items():
            blob = f"{name}: {value}"
            hits = keyword_hits(blob)
            if not hits:
                continue
            findings.append(
                emit_finding(
                    addon=ADDON_ID,
                    rule_id="MITM_SENSITIVE_HEADER",
                    evidence=(
                        f"proxy intercepted {method} {pretty} "
                        f"header {name}: {clip(str(value), 80)} "
                        f"keywords={','.join(hits)} "
                        f"[lab mitmproxy capture]"
                    ),
                    detail={
                        "method": method,
                        "url": pretty,
                        "location": "header",
                        "header": str(name),
                        "keywords": hits,
                        "value_clip": clip(str(value), 80),
                    },
                )
            )

    for location, blob in (
        ("request_body", str(flow.get("request_body") or "")),
        ("response_body", str(flow.get("response_body") or "")),
    ):
        hits = keyword_hits(blob)
        if not hits:
            continue
        # Prefer a short snippet around the first hit for evidence.
        snippet = clip(blob, 100)
        findings.append(
            emit_finding(
                addon=ADDON_ID,
                rule_id="MITM_SENSITIVE_BODY",
                evidence=(
                    f"proxy intercepted {method} {pretty} "
                    f"body keywords={','.join(hits)} {snippet} "
                    f"[lab mitmproxy capture]"
                ),
                detail={
                    "method": method,
                    "url": pretty,
                    "location": location,
                    "keywords": hits,
                    "snippet": snippet,
                },
            )
        )

    return findings


class SensitiveDataAddon:
    """mitmproxy addon: scan each completed exchange for sensitive keywords."""

    def response(self, flow) -> None:
        for finding in analyze_flow(flow_from_mitm(flow)):
            print_json(finding)


addons = [SensitiveDataAddon()]
