"""Unit tests for optional mitmproxy analyzer + Frida/lab SSL unpin wiring."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

import main as scan_main
from extra import mitmproxy_analyzer
from reporter.report_generator import ReportGenerator, sorted_findings
from rules.consolidate import consolidate_findings
from rules.owasp_mapper import OWASPMapper
from rules.rules_engine import RulesEngine
from webapp import exploit_grounding as g


FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "mitm_flows_sample.json"
)


class MitmproxyAnalyzerTests(unittest.TestCase):
    def test_parse_fixture_flows(self):
        with open(FIXTURE, encoding="utf-8") as handle:
            flows = mitmproxy_analyzer.parse_mitm_dump(handle.read())
        self.assertEqual(len(flows), 2)
        self.assertTrue(flows[0]["url"].startswith("http://"))

    def test_analyze_flows_emits_cleartext_and_sensitive(self):
        with open(FIXTURE, encoding="utf-8") as handle:
            flows = mitmproxy_analyzer.parse_mitm_dump(handle.read())
        _lines, findings = mitmproxy_analyzer.analyze_flows(flows)
        rules = {f["rule_id"] for f in findings}
        self.assertIn("MITM_CLEARTEXT_HTTP", rules)
        self.assertIn("MITM_SENSITIVE_HEADER", rules)
        self.assertIn("MITM_SENSITIVE_BODY", rules)
        self.assertTrue(
            any("proxy intercepted" in f["evidence"] for f in findings)
        )

    def test_run_with_offline_dump_env(self):
        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "com.android.insecurebankv2"
        with mock.patch.dict(os.environ, {"ANDROSEC_MITM_DUMP": FIXTURE}):
            result = mitmproxy_analyzer.run(ctx)
        self.assertFalse(result.get("skipped"))
        self.assertEqual(result["tool"], "mitmproxy")
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MITM_CLEARTEXT_HTTP", rules)

    def test_run_skips_without_dump_or_device(self):
        ctx = mock.Mock()
        env = {k: v for k, v in os.environ.items() if k != "ANDROSEC_MITM_DUMP"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "extra.mitmproxy_analyzer.device_ready",
            return_value=(False, "no device/emulator attached"),
        ), mock.patch("extra.mitmproxy_analyzer.shutil.which", return_value=None):
            result = mitmproxy_analyzer.run(ctx)
        self.assertTrue(result.get("skipped"))
        self.assertTrue(
            any(f["rule_id"] == "MITM_PROXY_NOT_READY" for f in result["findings"])
        )

    def test_har_parse(self):
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://evil.lab/x",
                            "headers": [{"name": "Cookie", "value": "a=1"}],
                            "postData": {},
                        },
                        "response": {"status": 200, "content": {"text": ""}},
                    }
                ]
            }
        }
        flows = mitmproxy_analyzer.parse_mitm_dump(json.dumps(har))
        self.assertEqual(len(flows), 1)
        _lines, findings = mitmproxy_analyzer.analyze_flows(flows)
        rules = {f["rule_id"] for f in findings}
        self.assertIn("MITM_CLEARTEXT_HTTP", rules)
        self.assertIn("MITM_SENSITIVE_HEADER", rules)

    def test_registered_in_main(self):
        ids = [tool_id for tool_id, _mod, _desc in scan_main.ANALYZERS]
        self.assertIn("mitmproxy", ids)
        self.assertIn("mitmproxy", scan_main.DYNAMIC_ANALYZERS)


class FridaScriptTests(unittest.TestCase):
    def test_runtime_monitor_contains_ssl_unpin(self):
        root = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(root, "scripts", "runtime_monitor.js")
        with open(path, encoding="utf-8") as handle:
            js = handle.read()
        self.assertIn("[SSL-Unpin]", js)
        self.assertIn("CertificatePinner", js)
        self.assertIn("SSLContext.init", js)
        self.assertIn("[HTTP] URL.openConnection", js)
        self.assertIn("SharedPreferences", js)

    def test_frida_analyzer_skips_without_frida(self):
        from analyzers import frida_runtime_analyzer

        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "jakhar.aseem.diva"
        with mock.patch.dict("sys.modules", {"frida": None}):
            # Force ImportError path by patching the import inside run.
            import builtins

            real_import = builtins.__import__

            def fake_import(name, *args, **kwargs):
                if name == "frida":
                    raise ImportError("no frida")
                return real_import(name, *args, **kwargs)

            with mock.patch("builtins.__import__", side_effect=fake_import):
                result = frida_runtime_analyzer.run(ctx)
        self.assertTrue(result.get("skipped"))
        self.assertEqual(result["tool"], "frida")


class MitmExploitAwarenessTests(unittest.TestCase):
    def _mitm_finding(self):
        return {
            "rule_id": "MITM_CLEARTEXT_HTTP",
            "title": "Cleartext HTTP via mitmproxy",
            "severity": "High",
            "evidence": (
                "proxy intercepted cleartext POST http://10.0.2.2:8888/login "
                "[lab mitmproxy capture]"
            ),
        }

    def test_classify_mitm_as_network_tls_not_auto(self):
        finding = self._mitm_finding()
        self.assertEqual(g.classify_finding(finding), "network_tls")
        self.assertFalse(g.is_auto_exploitable(finding))
        self.assertTrue(g.is_mitm_finding(finding))

    def test_plan_prompt_includes_network_capture_context(self):
        loaded = {
            "metadata": {"package": "com.android.insecurebankv2"},
            "summary": {},
            "finding": {
                "rule_id": "CODE_TRUST_ALL_CERTS",
                "title": "Trust all",
                "severity": "High",
                "evidence": "TrustAllCerts",
            },
        }
        prompt = g.plan_prompt(
            loaded,
            {"serial": "emu", "model": "Pixel", "android_version": "11"},
            [self._mitm_finding()],
        )
        self.assertIn("NETWORK_CAPTURE_CONTEXT", prompt)
        self.assertIn("MITM_CLEARTEXT_HTTP", prompt)
        self.assertIn("proxy intercepted", prompt)
        self.assertIn("AUTO_EXPLOITABLE: false", prompt)
        self.assertIn("HINT", prompt)

    def test_priority_bump_with_mitm_sibling(self):
        tls = {
            "rule_id": "CODE_TRUST_ALL_CERTS",
            "title": "Trust all",
            "severity": "High",
            "evidence": "TrustAll",
        }
        base = g.exploit_priority(tls, [])
        bumped = g.exploit_priority(tls, [self._mitm_finding()])
        self.assertGreater(bumped, base)

    def test_tls_echo_still_not_confirmed_with_mitm_context(self):
        loaded = {
            "metadata": {"package": "com.htbridge.pivaa"},
            "summary": {},
            "finding": {
                "rule_id": "CODE_TRUST_ALL_CERTS",
                "title": "Trust all certificates",
                "severity": "High",
                "evidence": "TrustAllCerts",
            },
            "findings": [self._mitm_finding()],
        }
        steps = [{
            "step": "echo",
            "command": "adb shell echo 'network_tls requires MITM proxy'",
            "result_summary": "network_tls requires MITM proxy",
        }]
        evaluation = g.evaluate_evidence(loaded, steps, [])
        self.assertNotEqual(evaluation["level"], "CONFIRMED")

    def test_not_auto_baseline_unchanged(self):
        loaded = {
            "metadata": {"package": "x"},
            "finding": self._mitm_finding(),
            "summary": {},
        }
        steps = g.finding_baseline_steps(loaded)
        self.assertTrue(
            any("ANDROSEC_NOT_AUTO" in s["command"].upper() for s in steps)
        )


class ReportPipelineTests(unittest.TestCase):
    def test_enrich_and_report_with_mitm_findings(self):
        raw = [
            {
                "rule_id": "MITM_CLEARTEXT_HTTP",
                "evidence": "proxy intercepted cleartext GET http://x/",
            },
            {
                "rule_id": "MITM_SENSITIVE_HEADER",
                "evidence": "proxy intercepted header Authorization: Bearer x",
            },
            {
                "rule_id": "RUNTIME_SSL_UNPIN",
                "evidence": "[SSL-Unpin] OkHttp CertificatePinner.check bypassed",
            },
        ]
        base = os.path.dirname(os.path.dirname(__file__))
        findings = RulesEngine(os.path.join(base, "rules", "rules.json")).enrich(raw)
        findings = OWASPMapper(
            os.path.join(base, "rules", "owasp_mapping.json")
        ).apply(findings)
        findings = consolidate_findings(findings)
        self.assertTrue(any(f.get("severity") == "High" for f in findings))
        self.assertTrue(all(f.get("masvs", "").startswith("MASVS-") for f in findings))

        ordered = sorted_findings(findings)
        self.assertEqual(len(ordered), len(findings))

        with tempfile.TemporaryDirectory() as tmp:
            reporter = ReportGenerator(
                {
                    "target": "lab.apk",
                    "target_basename": "lab.apk",
                    "timestamp": "2026-01-01 00:00:00",
                    "sha256": "abc",
                    "size_human": "1 MB",
                    "package": "com.android.insecurebankv2",
                    "app_name": "IB2",
                    "version_name": "1",
                    "min_sdk": "19",
                    "target_sdk": "28",
                },
                [
                    {
                        "tool": "mitmproxy",
                        "output": "ok",
                        "findings": raw[:2],
                        "skipped": False,
                    }
                ],
                findings,
                {"level": "HIGH", "score": 40, "counts": {"High": 2, "Info": 1}},
            )
            html_path = os.path.join(tmp, "r.html")
            json_path = os.path.join(tmp, "r.json")
            reporter.save_html(html_path)
            reporter.save_json(json_path)
            self.assertTrue(os.path.isfile(html_path))
            with open(json_path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertTrue(
                any(f["rule_id"].startswith("MITM_") for f in data["findings"])
            )


if __name__ == "__main__":
    unittest.main()
