"""Map rule ids to OWASP MASVS controls and link those controls in HTML reports.

Linking is based on the id shape ``MASVS-<GROUP>-<number>``, not on a fixed
list of findings. Any id the mapping assigns, including one added later, becomes
``<a href="masvs_explanations.html#MASVS-..." target="_blank">``. The report and
``masvs_explanations.html`` have to sit in the same directory. The default
output directory is ``output_reports/``.

``MASVS_V2_IDS`` is the OWASP MASVS v2 control set, in document order. The
explanations page has a section for each one. When a new id is added to
``owasp_mapping.json``, add a matching ``<section id="...">`` if it is not
already there. The report test fails while a mapped id has no section.
"""

import html
import json
import re

MASVS_ID = re.compile(r"^MASVS-[A-Z]+-\d+$")
EXPLANATIONS_PAGE = "masvs_explanations.html"

# OWASP MASVS v2 controls, in the order of the MASVS document.
MASVS_V2_IDS = (
    "MASVS-STORAGE-1",
    "MASVS-STORAGE-2",
    "MASVS-CRYPTO-1",
    "MASVS-CRYPTO-2",
    "MASVS-AUTH-1",
    "MASVS-AUTH-2",
    "MASVS-AUTH-3",
    "MASVS-NETWORK-1",
    "MASVS-NETWORK-2",
    "MASVS-PLATFORM-1",
    "MASVS-PLATFORM-2",
    "MASVS-PLATFORM-3",
    "MASVS-CODE-1",
    "MASVS-CODE-2",
    "MASVS-CODE-3",
    "MASVS-CODE-4",
    "MASVS-RESILIENCE-1",
    "MASVS-RESILIENCE-2",
    "MASVS-RESILIENCE-3",
    "MASVS-RESILIENCE-4",
    "MASVS-PRIVACY-1",
    "MASVS-PRIVACY-2",
    "MASVS-PRIVACY-3",
    "MASVS-PRIVACY-4",
)


def is_masvs_id(value):
    return bool(value) and MASVS_ID.match(value) is not None


def masvs_link(value):
    """Return the Findings-table cell contents for a MASVS value.

    A control id becomes a link to its anchor. ``N/A`` and anything else stay
    escaped text, so a missing mapping does not become a broken link.
    """
    text = value or "N/A"
    if not is_masvs_id(text):
        return html.escape(text)
    safe = html.escape(text, quote=True)
    return (f'<a href="{EXPLANATIONS_PAGE}#{safe}" '
            f'target="_blank">{safe}</a>')


def explanation_section_ids(html_text):
    """Return MASVS ids that have a section anchor in an explanations page."""
    return set(re.findall(r'id="(MASVS-[A-Z]+-\d+)"', html_text))


class OWASPMapper:
    def __init__(self, path):
        with open(path, encoding="utf-8") as f:
            self.map = json.load(f)

    def apply(self, findings):
        for f in findings:
            f["masvs"] = self.map.get(f["rule_id"], "N/A")
        return findings

    def masvs_ids(self):
        """Unique control ids this mapping can produce, in MASVS v2 order.

        An id that is not part of MASVS v2 is kept and sorted after the
        standard controls, so a later addition still links and still shows up
        in coverage checks.
        """
        found = {v for v in self.map.values() if is_masvs_id(v)}
        ordered = [i for i in MASVS_V2_IDS if i in found]
        extras = sorted(found.difference(MASVS_V2_IDS))
        return ordered + extras
