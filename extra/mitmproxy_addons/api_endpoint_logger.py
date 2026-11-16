"""API Endpoint Logger — unique method + path + host with a clean report."""

from __future__ import annotations

from typing import Any

try:
    from ._common import (
        emit_endpoint,
        emit_finding,
        flow_from_mitm,
        parse_url_parts,
        print_json,
    )
except ImportError:  # mitmdump -s
    from _common import (
        emit_endpoint,
        emit_finding,
        flow_from_mitm,
        parse_url_parts,
        print_json,
    )

ADDON_ID = "api_endpoint_logger"


def endpoint_key(method: str, host: str, path: str) -> str:
    return f"{method.upper()} {host}{path}"


def analyze_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a single endpoint record (or empty) for the flow."""
    method = str(flow.get("method") or "GET").upper()
    url = str(flow.get("url") or "")
    scheme, host, path, _pretty = parse_url_parts(url)
    if not host:
        return []
    return [
        emit_endpoint(method=method, host=host, path=path or "/", scheme=scheme)
    ]


def format_endpoint_report(endpoints: list[dict[str, Any]]) -> str:
    """Human-readable unique endpoint inventory."""
    lines = ["API endpoints (unique method+host+path):"]
    if not endpoints:
        lines.append("  (none)")
        return "\n".join(lines)
    for ep in endpoints:
        method = ep.get("method") or "GET"
        host = ep.get("host") or ""
        path = ep.get("path") or "/"
        scheme = ep.get("scheme") or ""
        prefix = f"{scheme}://" if scheme else ""
        lines.append(f"  {method} {prefix}{host}{path}")
    return "\n".join(lines)


def summary_finding(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    inventory = "; ".join(
        endpoint_key(e.get("method") or "GET", e.get("host") or "", e.get("path") or "/")
        for e in endpoints[:24]
    ) or "(no hosts)"
    return emit_finding(
        addon=ADDON_ID,
        rule_id="MITM_TRAFFIC_SUMMARY",
        evidence=(
            f"proxy intercepted {len(endpoints)} unique endpoint(s): {inventory}"
        ),
        detail={"endpoints": endpoints, "count": len(endpoints)},
    )


class ApiEndpointLoggerAddon:
    """Track unique API endpoints across the capture session."""

    def __init__(self) -> None:
        self._seen: dict[str, dict[str, Any]] = {}

    def response(self, flow) -> None:
        for record in analyze_flow(flow_from_mitm(flow)):
            key = endpoint_key(
                record.get("method") or "GET",
                record.get("host") or "",
                record.get("path") or "/",
            )
            if key in self._seen:
                continue
            self._seen[key] = record
            print_json(record)

    def done(self) -> None:
        endpoints = list(self._seen.values())
        report = format_endpoint_report(endpoints)
        # Emit report as a single JSON line for the analyzer/report text path.
        print_json(
            {
                "androsec": "mitm_report",
                "addon": ADDON_ID,
                "report": report,
            }
        )
        if endpoints:
            print_json(summary_finding(endpoints))


addons = [ApiEndpointLoggerAddon()]
