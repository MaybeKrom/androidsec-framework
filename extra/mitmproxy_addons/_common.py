"""Shared helpers for androsec mitmproxy addons (no mitmproxy import)."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

SENSITIVE_KEYWORDS = (
    "password",
    "token",
    "secret",
    "api_key",
    "authorization",
    "bearer",
)

_KEYWORD_RE = re.compile(
    r"(?i)\b(password|token|secret|api[_-]?key|authorization|bearer)\b"
)


def clip(text: str, n: int = 220) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def parse_url_parts(url: str) -> tuple[str, str, str, str]:
    """Return ``(scheme, host, path, pretty)``."""
    try:
        parsed = urlparse(url or "")
        scheme = (parsed.scheme or "").lower()
        host = parsed.netloc or ""
        path = parsed.path or "/"
        pretty = f"{scheme}://{host}{path}" if scheme and host else (url or "")[:160]
        return scheme, host, path, pretty
    except Exception:
        return "", "", "/", (url or "")[:160]


def keyword_hits(text: str) -> list[str]:
    if not text:
        return []
    found = []
    seen = set()
    for match in _KEYWORD_RE.finditer(text):
        key = match.group(1).lower().replace("-", "_")
        if key == "api-key":
            key = "api_key"
        if key not in seen:
            seen.add(key)
            found.append(key)
    return found


def emit_finding(
    *,
    addon: str,
    rule_id: str,
    evidence: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Structured JSON finding line consumed by ``mitmproxy_analyzer``."""
    obj: dict[str, Any] = {
        "androsec": "mitm_finding",
        "addon": addon,
        "rule_id": rule_id,
        "evidence": evidence,
    }
    if detail:
        obj["detail"] = detail
    return obj


def emit_endpoint(
    *,
    method: str,
    host: str,
    path: str,
    scheme: str = "",
) -> dict[str, Any]:
    return {
        "androsec": "mitm_endpoint",
        "addon": "api_endpoint_logger",
        "method": method,
        "host": host,
        "path": path,
        "scheme": scheme,
    }


def print_json(obj: dict[str, Any]) -> None:
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def flow_from_mitm(flow) -> dict[str, Any]:
    """Normalize a mitmproxy HTTPFlow into the analyzer's flat flow dict."""
    req = flow.request
    headers = {k: v for k, v in req.headers.items(multi=True)}
    body = ""
    try:
        body = req.get_text(strict=False) or ""
    except Exception:
        body = ""
    resp_body = ""
    status = None
    if flow.response is not None:
        status = flow.response.status_code
        try:
            resp_body = flow.response.get_text(strict=False) or ""
        except Exception:
            resp_body = ""
    return {
        "method": str(req.method or "GET"),
        "url": str(req.pretty_url or ""),
        "headers": headers,
        "request_body": body,
        "status": status,
        "response_body": resp_body,
    }


def dump_flow_record(flow) -> dict[str, Any]:
    """NDJSON flow record compatible with ``parse_mitm_dump``."""
    flat = flow_from_mitm(flow)
    headers = [[k, v] for k, v in (flat.get("headers") or {}).items()]
    return {
        "request": {
            "method": flat["method"],
            "url": flat["url"],
            "headers": headers,
            "content": flat.get("request_body") or "",
        },
        "response": {
            "status_code": flat.get("status"),
            "text": flat.get("response_body") or "",
        },
    }
