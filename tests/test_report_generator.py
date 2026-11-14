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

    def test_each_finding_links_to_a_review(self):
        findings = [
            {
                "severity": "Info",
                "confidence": "Low",
                "rule_id": "NOTE",
                "title": "No mapping",
                "evidence": "n/a",
                "recommendation": "None",
                "masvs": "N/A",
            },
            {
                "severity": "High",
                "confidence": "High",
                "rule_id": "EXPORTED",
                "title": "Exported component",
                "evidence": "activity",
                "recommendation": "Set exported false",
                "masvs": "MASVS-PLATFORM-1",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "security_report_20261111_120000.html")
            _report(findings).save_html(path)
            report_html = Path(path).read_text(encoding="utf-8")
        self.assertIn(
            'href="/review?report=security_report_20261111_120000.html&amp;i=0"',
            report_html,
        )
        self.assertLess(
            report_html.index("Exported component"),
            report_html.index("No mapping"),
        )
        self.assertIn(">Review</a>", report_html)


class TestPdfReport(unittest.TestCase):
    def test_html_findings_column_is_vulnerability(self):
        findings = [
            {
                "severity": "High",
                "confidence": "High",
                "rule_id": "EXPORTED",
                "title": "Exported component",
                "evidence": "activity",
                "recommendation": "Set exported false",
                "masvs": "MASVS-PLATFORM-1",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "security_report_sample.html")
            _report(findings).save_html(path)
            report_html = Path(path).read_text(encoding="utf-8")
        self.assertIn("<th>Vulnerability</th>", report_html)
        self.assertNotIn("<th>Title</th>", report_html)

    def test_pdf_document_keeps_the_assessment_and_the_disclaimer(self):
        from reporter.pdf_report import DISCLAIMER

        findings = [
            {
                "severity": "High",
                "confidence": "High",
                "rule_id": "RESILIENCE_ROOT_CHECK_PRESENT",
                "title": "Root detection implemented",
                "description": "A root check is present.",
                "evidence": "isrooted",
                "recommendation": "Keep the check.",
                "masvs": "MASVS-RESILIENCE-1",
            }
        ]
        tools = [
            {"tool": "apk_info", "output": "=== APK Information ===", "skipped": False, "finding_count": 1},
            {"tool": "frida", "output": "device required", "skipped": True},
            {"tool": "legacy", "output": "old record", "skipped": False},
        ]
        report = ReportGenerator(
            {
                "target": "sample.apk",
                "target_basename": "sample.apk",
                "timestamp": "2026-11-11 00:00:00",
                "sha256": "abc",
                "package": "example.app",
                "score": 0,
            },
            tools,
            findings,
            {"level": "HIGH", "score": 40, "counts": {"High": 1}},
        )
        document = report.render_pdf_html()
        self.assertEqual(
            DISCLAIMER,
            "This report is an automated assessment and provides an approximate security "
            "overview. It is not guaranteed to be 100% accurate. Some vulnerabilities may "
            "not have been detected.",
        )
        self.assertEqual(document.count(DISCLAIMER), 1)
        self.assertIn("main > section.closing", document)
        self.assertIn("androsec", document)
        self.assertIn("Executive summary", document)
        self.assertIn(">Vulnerability</th>", document)
        self.assertIn("apk_info", document)
        self.assertIn("1 finding", document)
        self.assertIn("Skipped", document)
        self.assertNotIn("0 findings", document)
        self.assertIn("Root detection implemented", document)
        self.assertIn("isrooted", document)
        self.assertNotIn("<th>Title</th>", document)

    def test_save_pdf_writes_a_pdf(self):
        findings = [
            {
                "severity": "Info",
                "confidence": "Low",
                "rule_id": "NOTE",
                "title": "Launcher activity",
                "evidence": "MainActivity",
                "recommendation": "None",
                "masvs": "N/A",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.pdf")
            _report(findings).save_pdf(path)
            data = Path(path).read_bytes()
        self.assertTrue(data.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
