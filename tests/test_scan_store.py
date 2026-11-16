"""Path layout + finding↔evidence linking for unified scan folders."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reporter.report_generator import ReportGenerator, sorted_findings
from reporter.scan_store import (
    append_commands_output,
    create_scan_dir,
    dual_write_tree,
    exploitation_evidence_dir,
    exploitation_pdf_name,
    finding_id_for,
    find_scan_dir_for_legacy_report,
    make_scan_id,
    read_index,
    register_exploitation,
    resolve_scan_dir_from_metadata,
    safe_app_name,
    sync_assessment_pdf,
    write_assessment_bundle,
)


class TestScanNaming(unittest.TestCase):
    def test_safe_app_name_strips_unsafe(self):
        self.assertEqual(safe_app_name("Insecure Bank v2!"), "Insecure_Bank_v2")
        self.assertEqual(safe_app_name(""), "App")
        self.assertEqual(safe_app_name("@@@"), "App")

    def test_make_scan_id(self):
        self.assertEqual(
            make_scan_id("20261116_031200", "InsecureBankv2"),
            "scan_20261116_031200_InsecureBankv2",
        )

    def test_finding_id_stable(self):
        self.assertEqual(
            finding_id_for(0, "COMPONENT_PROVIDER"),
            "F000_COMPONENT_PROVIDER",
        )
        self.assertEqual(finding_id_for(12, "SECRET AWS"), "F012_SECRET_AWS")


class TestScanLayout(unittest.TestCase):
    def test_create_and_write_assessment_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans_root = os.path.join(tmp, "scans")
            legacy = os.path.join(tmp, "output_reports")
            stamp = "20261116_031200"
            scan = create_scan_dir(
                scans_root,
                stamp,
                "InsecureBankv2",
                package="com.android.insecurebankv2",
                apk_basename="InsecureBankv2.apk",
                sha256="abc",
            )
            self.assertTrue(os.path.isdir(scan["evidence_dir"]))
            self.assertTrue(os.path.isfile(os.path.join(scan["scan_dir"], "index.json")))

            findings = sorted_findings([
                {
                    "severity": "High",
                    "rule_id": "COMPONENT_PROVIDER",
                    "title": "Exported provider",
                    "evidence": "content://lab/notes",
                    "recommendation": "Restrict export",
                    "masvs": "MASVS-PLATFORM-1",
                    "confidence": "High",
                },
                {
                    "severity": "Info",
                    "rule_id": "LAB_CHALLENGE",
                    "title": "Lab",
                    "evidence": "n/a",
                    "recommendation": "",
                    "masvs": "N/A",
                    "confidence": "Low",
                },
            ])
            metadata = {
                "target": "InsecureBankv2.apk",
                "target_basename": "InsecureBankv2.apk",
                "timestamp": "2026-11-16 03:12:00",
                "sha256": "abc",
                "package": "com.android.insecurebankv2",
                "app_name": "InsecureBankv2",
                "scan_id": scan["scan_id"],
                "scan_dir": scan["scan_dir"],
                "report_stamp": stamp,
            }
            summary = {
                "level": "HIGH",
                "score": 40,
                "counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 1},
            }
            reporter = ReportGenerator(metadata, [], findings, summary)
            paths = write_assessment_bundle(
                scan["scan_dir"],
                stamp,
                reporter,
                sorted_findings_list=findings,
                legacy_reports_dir=legacy,
            )

            self.assertTrue(os.path.isfile(paths["assessment_html"]))
            self.assertTrue(os.path.isfile(paths["assessment_json"]))
            self.assertTrue(os.path.isfile(paths["legacy_html"]))
            self.assertTrue(os.path.isfile(paths["flat_html"]))
            self.assertEqual(
                os.path.basename(paths["html_path"]),
                f"security_report_{stamp}.html",
            )

            index = read_index(scan["scan_dir"])
            self.assertEqual(index["scan_id"], scan["scan_id"])
            self.assertEqual(len(index["findings"]), 2)
            self.assertEqual(index["findings"][0]["finding_id"], "F000_COMPONENT_PROVIDER")
            self.assertEqual(index["findings"][0]["index"], 0)
            self.assertEqual(index["assessment"]["html"], "assessment_report.html")

            with open(paths["flat_json"], encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["metadata"]["scan_id"], scan["scan_id"])

    def test_register_exploitation_links_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp = "20261116_040000"
            scan = create_scan_dir(tmp, stamp, "DIVA")
            run_id = "exploitation_20261116_040100"
            dest = exploitation_evidence_dir(scan["scan_dir"], run_id)
            Path(dest, "screenshot_01.png").write_bytes(b"png")
            Path(dest, "commands_output.txt").write_text("$ adb shell\nok\n", encoding="utf-8")
            pdf_name = exploitation_pdf_name("F000_COMPONENT_PROVIDER", run_id)
            Path(scan["scan_dir"], pdf_name).write_bytes(b"%PDF")

            entry = register_exploitation(
                scan["scan_dir"],
                finding_id="F000_COMPONENT_PROVIDER",
                rule_id="COMPONENT_PROVIDER",
                index=0,
                run_id=run_id,
                confirmation="CONFIRMED",
                pdf_relpath=pdf_name,
            )
            self.assertEqual(entry["finding_id"], "F000_COMPONENT_PROVIDER")
            self.assertEqual(entry["evidence_dir"], f"evidence/{run_id}")

            index = read_index(scan["scan_dir"])
            self.assertEqual(len(index["exploitations"]), 1)
            linked = index["exploitations"][0]
            self.assertEqual(linked["rule_id"], "COMPONENT_PROVIDER")
            self.assertEqual(linked["pdf"], pdf_name)
            self.assertTrue(
                os.path.isdir(os.path.join(scan["scan_dir"], linked["evidence_dir"]))
            )
            self.assertTrue(os.path.isfile(os.path.join(scan["scan_dir"], linked["pdf"])))

            # Re-register same run_id replaces rather than duplicates.
            register_exploitation(
                scan["scan_dir"],
                finding_id="F000_COMPONENT_PROVIDER",
                rule_id="COMPONENT_PROVIDER",
                index=0,
                run_id=run_id,
                confirmation="PARTIAL",
                pdf_relpath=pdf_name,
            )
            index = read_index(scan["scan_dir"])
            self.assertEqual(len(index["exploitations"]), 1)
            self.assertEqual(index["exploitations"][0]["confirmation"], "PARTIAL")

    def test_dual_write_and_resolve_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "exploitations", "exploitation_1")
            dest = os.path.join(tmp, "scans", "scan_x", "evidence", "exploitation_1")
            os.makedirs(src)
            Path(src, "screenshot_01.png").write_bytes(b"x")
            Path(src, "report.pdf").write_bytes(b"%PDF")
            dual_write_tree(src, dest)
            self.assertTrue(os.path.isfile(os.path.join(dest, "screenshot_01.png")))
            self.assertTrue(os.path.isfile(os.path.join(dest, "report.pdf")))

            scan = create_scan_dir(os.path.join(tmp, "scans"), "20261116_050000", "App")
            meta = {
                "scan_id": scan["scan_id"],
                "scan_dir": os.path.relpath(scan["scan_dir"], tmp),
            }
            # resolve with project-style absolute scan_dir in metadata
            meta_abs = {"scan_id": scan["scan_id"], "scan_dir": scan["scan_dir"]}
            self.assertEqual(
                resolve_scan_dir_from_metadata(meta_abs, scans_root=os.path.join(tmp, "scans")),
                os.path.realpath(scan["scan_dir"]),
            )

            # Legacy report name lookup
            Path(scan["scan_dir"], "security_report_20261116_050000.json").write_text(
                "{}", encoding="utf-8"
            )
            found = find_scan_dir_for_legacy_report(
                "security_report_20261116_050000.html",
                scans_root=os.path.join(tmp, "scans"),
            )
            self.assertEqual(found, os.path.realpath(scan["scan_dir"]))

    def test_append_commands_and_sync_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = create_scan_dir(tmp, "20261116_060000", "App")
            steps = [{
                "title": "Query provider",
                "command": "adb shell content query --uri content://lab/notes",
                "result_summary": "OK",
                "stdout": "Row: 1 name=alice",
            }]
            path = append_commands_output(scan["evidence_dir"], steps)
            text = Path(path).read_text(encoding="utf-8")
            self.assertIn("adb shell content query", text)
            self.assertIn("Row: 1 name=alice", text)

            src_pdf = os.path.join(tmp, "built.pdf")
            Path(src_pdf).write_bytes(b"%PDF-1.4")
            synced = sync_assessment_pdf(scan["scan_dir"], "20261116_060000", src_pdf)
            self.assertTrue(os.path.isfile(synced["assessment_pdf"]))
            self.assertTrue(os.path.isfile(synced["legacy_pdf"]))


class TestRunScanIntegration(unittest.TestCase):
    def test_run_scan_creates_unified_layout(self):
        """Smoke: run_scan with mocked analyzers writes scan folder + dual-write."""
        import main as scan_main

        class FakeCtx:
            def __init__(self, apk):
                self.apk_path = apk
                self.sha256 = "deadbeef"
                self.apk = FakeApk()

            def get_manifest_root(self):
                return None

        class FakeApk:
            def get_package(self):
                return "com.example.lab"

            def get_app_name(self):
                return "LabApp"

            def get_androidversion_name(self):
                return "1.0"

            def get_target_sdk_version(self):
                return "30"

            def get_min_sdk_version(self):
                return "21"

        def fake_run(_ctx):
            return {
                "tool": "manifest",
                "output": "ok",
                "findings": [{
                    "rule_id": "MANIFEST_DEBUGGABLE",
                    "evidence": "debuggable=true",
                }],
                "skipped": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            apk = os.path.join(tmp, "LabApp.apk")
            Path(apk).write_bytes(b"PK\x03\x04fake")
            scans_root = os.path.join(tmp, "scans")
            legacy = os.path.join(tmp, "output_reports")

            with mock.patch.object(scan_main, "AppContext", FakeCtx), \
                 mock.patch.object(scan_main, "ANALYZERS", [
                     ("manifest", "analyzers.manifest_analyzer", "test"),
                 ]), \
                 mock.patch("analyzers.manifest_analyzer.run", fake_run), \
                 mock.patch.object(scan_main, "DYNAMIC_ANALYZERS", set()):
                # RulesEngine/OWASP need real rules; use only enrichment-safe path.
                result = scan_main.run_scan(
                    apk,
                    output_dir=scans_root,
                    only=["manifest"],
                    static_only=True,
                    start_adb=False,
                    legacy_reports_dir=legacy,
                )

            self.assertTrue(result["scan_id"].startswith("scan_"))
            self.assertTrue(os.path.isdir(result["scan_dir"]))
            self.assertTrue(
                os.path.isfile(os.path.join(result["scan_dir"], "assessment_report.html"))
            )
            self.assertTrue(
                os.path.isfile(os.path.join(result["scan_dir"], "assessment_report.json"))
            )
            self.assertTrue(os.path.isfile(os.path.join(result["scan_dir"], "index.json")))
            self.assertTrue(os.path.isfile(result["html_path"]))
            self.assertTrue(result["html_path"].startswith(legacy))
            self.assertEqual(result["metadata"]["scan_id"], result["scan_id"])

            index = read_index(result["scan_dir"])
            self.assertGreaterEqual(len(index["findings"]), 1)
            self.assertTrue(index["findings"][0]["finding_id"].startswith("F000_"))


if __name__ == "__main__":
    unittest.main()
