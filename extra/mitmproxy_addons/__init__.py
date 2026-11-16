"""Practical mitmproxy addons for androsec lab traffic analysis.

Each module exposes pure ``analyze_flow`` helpers (unit-testable without
mitmproxy) plus an Addon class for ``mitmdump -s``. Live capture loads
``loader.py``, which registers all addons and dumps normalized flows.
"""

from __future__ import annotations

import os

ADDON_DIR = os.path.dirname(os.path.abspath(__file__))
LOADER_SCRIPT = os.path.join(ADDON_DIR, "loader.py")

# Scripts suitable for ``mitmdump -s`` (loader includes all analysis addons).
ADDON_SCRIPTS = (
    "sensitive_data.py",
    "cleartext_http.py",
    "api_endpoint_logger.py",
    "auth_header_capture.py",
)


def addon_script_paths() -> list[str]:
    """Absolute paths to individual addon scripts (excluding loader)."""
    return [os.path.join(ADDON_DIR, name) for name in ADDON_SCRIPTS]


def loader_script_path() -> str:
    """Entrypoint used by the analyzer for live ``mitmdump -s`` capture."""
    return LOADER_SCRIPT
