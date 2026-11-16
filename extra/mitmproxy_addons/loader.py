"""Combined mitmproxy entrypoint for androsec live capture.

Usage::

    mitmdump -s extra/mitmproxy_addons/loader.py -p 8080

Emits NDJSON to stdout:
- flow dump records (``request`` / ``response``) for offline-compatible parsing
- ``androsec: mitm_finding`` lines from analysis addons
- ``androsec: mitm_endpoint`` / ``mitm_report`` from the API endpoint logger
"""

from __future__ import annotations

import os
import sys

# Allow ``mitmdump -s /abs/path/loader.py`` to import sibling modules.
_ADDON_DIR = os.path.dirname(os.path.abspath(__file__))
if _ADDON_DIR not in sys.path:
    sys.path.insert(0, _ADDON_DIR)

from _common import dump_flow_record, print_json  # noqa: E402
from api_endpoint_logger import ApiEndpointLoggerAddon  # noqa: E402
from auth_header_capture import AuthHeaderCaptureAddon  # noqa: E402
from cleartext_http import CleartextHttpAddon  # noqa: E402
from sensitive_data import SensitiveDataAddon  # noqa: E402


class FlowDumpAddon:
    """Preserve the analyzer's NDJSON flow dump format alongside findings."""

    def response(self, flow) -> None:
        print_json(dump_flow_record(flow))


addons = [
    FlowDumpAddon(),
    SensitiveDataAddon(),
    CleartextHttpAddon(),
    ApiEndpointLoggerAddon(),
    AuthHeaderCaptureAddon(),
]
