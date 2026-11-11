import json
import os
import tempfile
import unittest
from pathlib import Path

from reporter.report_generator import ReportGenerator, masvs_cell
from rules.owasp_mapper import (
    MASVS_V2_IDS,
    OWASPMapper,
    explanation_section_ids,
    masvs_link,
)


def _report(findings):
    metadata = {
        "target": "sample.apk",
        "timestamp": "2026-11-11 00:00:00",
        "sha256": "abc",
    }
    summary = {"level": "LOW", "score": 0, "counts": {}}
    return ReportGenerator(metadata, [], findings, summary)


class TestMasvsLinks(unittest.TestCase):
    def test_masvs_cell_links_control_ids_only(self):
        linked = masvs_cell("MASVS-PLATFORM-1")
        self.assertEqual(
            linked,
            '<a href="masvs_explanations.html#MASVS-PLATFORM-1" '
            'target="_blank">MASVS-PLATFORM-1</a>',
        )
        self.assertEqual(masvs_cell("N/A"), "N/A")
        self.assertEqual(masvs_cell(""), "N/A")
        self.assertEqual(masvs_cell("not-a-control"), "not-a-control")

    def test_html_findings_table_links_masvs(self):
        findings = [
            {
                "severity": "High",
                "confidence": "High",
                "rule_id": "EXPORTED",
                "title": "Exported component",
                "evidence": "activity",
                "recommendation": "Set exported false",
                "masvs": "MASVS-PLATFORM-1",
            },
            {
                "severity": "Info",
                "confidence": "Low",
                "rule_id": "NOTE",
                "title": "No mapping",
                "evidence": "n/a",
                "recommendation": "None",
                "masvs": "N/A",
            },
        ]
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            path = tf.name
        try:
            _report(findings).save_html(path)
            with open(path, encoding="utf-8") as fh:
                report_html = fh.read()
        finally:
            if os.path.exists(path):
                os.remove(path)
        self.assertIn(
            '<td><a href="masvs_explanations.html#MASVS-PLATFORM-1" '
            'target="_blank">MASVS-PLATFORM-1</a></td>',
            report_html,
        )
        self.assertIn("<td>N/A</td>", report_html)
        self.assertNotIn('href="masvs_explanations.html#N/A"', report_html)

    def test_every_mapped_and_standard_id_has_a_section_and_links(self):
        base = Path(__file__).resolve().parents[1]
        page = (base / "output_reports" / "masvs_explanations.html").read_text(encoding="utf-8")
        sections = explanation_section_ids(page)
        self.assertEqual(list(MASVS_V2_IDS), [i for i in MASVS_V2_IDS if i in sections])
        missing_standard = [i for i in MASVS_V2_IDS if i not in sections]
        self.assertEqual(missing_standard, [])

        mapper = OWASPMapper(str(base / "rules" / "owasp_mapping.json"))
        mapped = mapper.masvs_ids()
        missing_mapped = [i for i in mapped if f'id="{i}"' not in page]
        self.assertEqual(missing_mapped, [], "mapping ids without an explanation section")
        for masvs_id in mapped:
            self.assertIn(f'href="#{masvs_id}"', page)
            self.assertEqual(masvs_cell(masvs_id), masvs_link(masvs_id))
            self.assertIn(f'masvs_explanations.html#{masvs_id}', masvs_link(masvs_id))

        for heading in (
            "Security controls and focus areas",
            "Common vulnerabilities and attacks",
            "How these issues are usually exploited",
            "OWASP Mobile Top 10 (2024)",
            "Typical severity",
            "Suggested CVSS range",
            "Common CWEs",
        ):
            self.assertEqual(page.count(heading), len(MASVS_V2_IDS), heading)

        reports = sorted((base / "output_reports").glob("security_report_*.json"))
        self.assertTrue(reports)
        data = json.loads(reports[-1].read_text(encoding="utf-8"))
        # One extra row for an id the sample report never emitted, to show the
        # link is driven by the id shape rather than by that report.
        findings = list(data["findings"]) + [{
            "severity": "Info",
            "confidence": "Low",
            "rule_id": "FUTURE_RULE",
            "title": "Future mapping",
            "evidence": "n/a",
            "recommendation": "None",
            "masvs": "MASVS-CODE-4",
        }]
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            path = tf.name
        try:
            ReportGenerator(data["metadata"], [], findings, data["summary"]).save_html(path)
            with open(path, encoding="utf-8") as fh:
                report_html = fh.read()
        finally:
            if os.path.exists(path):
                os.remove(path)
        linked = {
            f["masvs"] for f in findings if str(f.get("masvs", "")).startswith("MASVS-")
        }
        for masvs_id in linked:
            self.assertIn(
                f'<td><a href="masvs_explanations.html#{masvs_id}" '
                f'target="_blank">{masvs_id}</a></td>',
                report_html,
            )
            self.assertIn(masvs_id, sections)


if __name__ == "__main__":
    unittest.main()
