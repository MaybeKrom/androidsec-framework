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
ADDON_FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "mitm_addon_findings.ndjson"
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

    def test_offline_dump_does_not_touch_adb_proxy(self):
        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "com.android.insecurebankv2"
        with mock.patch.dict(os.environ, {"ANDROSEC_MITM_DUMP": FIXTURE}), mock.patch(
            "extra.mitmproxy_analyzer.set_device_http_proxy"
        ) as set_proxy, mock.patch(
            "extra.mitmproxy_analyzer.clear_device_http_proxy"
        ) as clear_proxy, mock.patch(
            "extra.mitmproxy_analyzer._live_capture"
        ) as live:
            result = mitmproxy_analyzer.run(ctx)
        self.assertFalse(result.get("skipped"))
        set_proxy.assert_not_called()
        clear_proxy.assert_not_called()
        live.assert_not_called()


class MitmproxyAutoProxyTests(unittest.TestCase):
    """Mock ADB: proxy must be set before capture and cleared afterward."""

    def _completed(self, code=0, stdout="", stderr=""):
        return mock.Mock(returncode=code, stdout=stdout, stderr=stderr)

    def _adb_side_effect(self, *args, **kwargs):
        # args[0] is the full argv list when patching subprocess.run with _adb_cmd,
        # but _adb_cmd builds ["adb", *args] — tests patch _adb_cmd / helpers.
        return self._completed(0)

    def test_resolve_proxy_host_override_and_hints(self):
        with mock.patch.dict(
            os.environ, {"ANDROSEC_MITM_HOST": "192.168.56.1"}, clear=False
        ):
            host, reason = mitmproxy_analyzer.resolve_proxy_host()
            self.assertEqual(host, "192.168.56.1")
            self.assertIn("ANDROSEC_MITM_HOST", reason)

        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("ANDROSEC_MITM_HOST", "ANDROSEC_DEVICE_HINT")
        }
        env["ANDROSEC_DEVICE_HINT"] = "genymotion"
        env["ANDROSEC_GENYMOTION_HOST"] = "10.0.3.2"
        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "extra.mitmproxy_analyzer._adb_getprop", return_value=""
        ):
            host, reason = mitmproxy_analyzer.resolve_proxy_host()
            self.assertEqual(host, "10.0.3.2")
            self.assertIn("genymotion", reason.lower())

    def test_resolve_proxy_host_detects_avd_and_genymotion_props(self):
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("ANDROSEC_MITM_HOST", "ANDROSEC_DEVICE_HINT")
        }

        def getprop_avd(prop):
            return {
                "ro.kernel.qemu": "1",
                "ro.hardware": "ranchu",
                "ro.product.model": "sdk_gphone64_x86_64",
            }.get(prop, "")

        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "extra.mitmproxy_analyzer._adb_getprop", side_effect=getprop_avd
        ):
            host, reason = mitmproxy_analyzer.resolve_proxy_host()
            self.assertEqual(host, "10.0.2.2")
            self.assertIn("Emulator", reason)

        def getprop_geny(prop):
            return {
                "ro.product.manufacturer": "Genymotion",
                "ro.hardware": "vbox86",
                "ro.product.model": "Google Pixel 5",
            }.get(prop, "")

        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "extra.mitmproxy_analyzer._adb_getprop", side_effect=getprop_geny
        ):
            host, reason = mitmproxy_analyzer.resolve_proxy_host()
            self.assertEqual(host, "10.0.3.2")
            self.assertIn("Genymotion", reason)

    def test_set_and_clear_device_proxy_adb_commands(self):
        calls = []

        def fake_adb(*args, **kwargs):
            calls.append(list(args))
            return self._completed(0)

        with mock.patch("extra.mitmproxy_analyzer._adb_cmd", side_effect=fake_adb):
            ok, msg = mitmproxy_analyzer.set_device_http_proxy("10.0.2.2", 8080)
            self.assertTrue(ok)
            self.assertEqual(msg, "10.0.2.2:8080")
            ok, msg = mitmproxy_analyzer.clear_device_http_proxy()
            self.assertTrue(ok)
            self.assertEqual(msg, ":0")

        self.assertEqual(
            calls[0],
            ["shell", "settings", "put", "global", "http_proxy", "10.0.2.2:8080"],
        )
        self.assertEqual(
            calls[1],
            ["shell", "settings", "put", "global", "http_proxy", ":0"],
        )

    def test_live_capture_sets_proxy_before_and_clears_after(self):
        order = []
        popen_cmds = []

        def fake_set(host, port):
            order.append(("set", f"{host}:{port}"))
            return True, f"{host}:{port}"

        def fake_clear():
            order.append(("clear", ":0"))
            return True, ":0"

        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        fake_proc.wait.return_value = 0

        def fake_popen(cmd, *args, **kwargs):
            popen_cmds.append(list(cmd))
            return fake_proc

        with tempfile.TemporaryDirectory() as tmp:
            dump_path = os.path.join(tmp, "flows.ndjson")
            with mock.patch(
                "extra.mitmproxy_analyzer.shutil.which", return_value="/usr/bin/mitmdump"
            ), mock.patch(
                "extra.mitmproxy_analyzer._port_is_listening", return_value=False
            ), mock.patch(
                "extra.mitmproxy_analyzer.resolve_proxy_host",
                return_value=("10.0.2.2", "test"),
            ), mock.patch(
                "extra.mitmproxy_analyzer.set_device_http_proxy", side_effect=fake_set
            ), mock.patch(
                "extra.mitmproxy_analyzer.clear_device_http_proxy", side_effect=fake_clear
            ), mock.patch(
                "extra.mitmproxy_analyzer.subprocess.Popen", side_effect=fake_popen
            ), mock.patch(
                "extra.mitmproxy_analyzer._adb_cmd", return_value=self._completed(0)
            ), mock.patch(
                "extra.mitmproxy_analyzer.time.sleep"
            ), mock.patch.dict(
                os.environ, {"ANDROSEC_MITM_SECONDS": "3"}, clear=False
            ):
                ok, msg = mitmproxy_analyzer._live_capture(
                    "com.android.insecurebankv2", dump_path
                )

        self.assertTrue(ok)
        self.assertIn("10.0.2.2:8080", msg)
        self.assertEqual(order[0][0], "set")
        self.assertEqual(order[-1][0], "clear")
        self.assertIn(("set", "10.0.2.2:8080"), order)
        self.assertIn(("clear", ":0"), order)
        fake_proc.terminate.assert_called()
        self.assertTrue(popen_cmds)
        self.assertIn("-s", popen_cmds[0])
        script = popen_cmds[0][popen_cmds[0].index("-s") + 1]
        self.assertTrue(script.endswith("loader.py"))
        self.assertTrue(os.path.isfile(script))

    def test_live_capture_clears_proxy_when_set_fails(self):
        order = []

        def fake_set(host, port):
            order.append("set")
            return False, "adb denied"

        def fake_clear():
            order.append("clear")
            return True, ":0"

        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None

        with tempfile.TemporaryDirectory() as tmp:
            dump_path = os.path.join(tmp, "flows.ndjson")
            with mock.patch(
                "extra.mitmproxy_analyzer.shutil.which", return_value="/usr/bin/mitmdump"
            ), mock.patch(
                "extra.mitmproxy_analyzer._port_is_listening", return_value=False
            ), mock.patch(
                "extra.mitmproxy_analyzer.resolve_proxy_host",
                return_value=("10.0.2.2", "test"),
            ), mock.patch(
                "extra.mitmproxy_analyzer.set_device_http_proxy", side_effect=fake_set
            ), mock.patch(
                "extra.mitmproxy_analyzer.clear_device_http_proxy", side_effect=fake_clear
            ), mock.patch(
                "extra.mitmproxy_analyzer.subprocess.Popen", return_value=fake_proc
            ), mock.patch(
                "extra.mitmproxy_analyzer.time.sleep"
            ):
                ok, msg = mitmproxy_analyzer._live_capture("pkg", dump_path)

        self.assertFalse(ok)
        self.assertIn("could not set device proxy", msg)
        self.assertEqual(order, ["set", "clear"])

    def test_live_capture_clears_proxy_on_mid_capture_exception(self):
        order = []

        def fake_set(host, port):
            order.append("set")
            return True, f"{host}:{port}"

        def fake_clear():
            order.append("clear")
            return True, ":0"

        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None

        with tempfile.TemporaryDirectory() as tmp:
            dump_path = os.path.join(tmp, "flows.ndjson")
            with mock.patch(
                "extra.mitmproxy_analyzer.shutil.which", return_value="/usr/bin/mitmdump"
            ), mock.patch(
                "extra.mitmproxy_analyzer._port_is_listening", return_value=False
            ), mock.patch(
                "extra.mitmproxy_analyzer.resolve_proxy_host",
                return_value=("10.0.2.2", "test"),
            ), mock.patch(
                "extra.mitmproxy_analyzer.set_device_http_proxy", side_effect=fake_set
            ), mock.patch(
                "extra.mitmproxy_analyzer.clear_device_http_proxy", side_effect=fake_clear
            ), mock.patch(
                "extra.mitmproxy_analyzer.subprocess.Popen", return_value=fake_proc
            ), mock.patch(
                "extra.mitmproxy_analyzer._adb_cmd",
                side_effect=RuntimeError("monkey boom"),
            ), mock.patch(
                # sleep after monkey; raise on the capture wait sleep
                "extra.mitmproxy_analyzer.time.sleep",
                side_effect=[None, RuntimeError("capture interrupted")],
            ):
                ok, msg = mitmproxy_analyzer._live_capture("pkg.lab", dump_path)

        self.assertFalse(ok)
        self.assertIn("live capture failed", msg)
        self.assertEqual(order, ["set", "clear"])

    def test_run_live_skips_gracefully_when_proxy_fails(self):
        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "jakhar.aseem.diva"
        env = {k: v for k, v in os.environ.items() if k != "ANDROSEC_MITM_DUMP"}
        with tempfile.TemporaryDirectory() as tmp:
            env["ANDROSEC_OUTPUT_DIR"] = tmp
            with mock.patch.dict(os.environ, env, clear=True), mock.patch(
                "extra.mitmproxy_analyzer.device_ready", return_value=(True, "")
            ), mock.patch(
                "extra.mitmproxy_analyzer.shutil.which", return_value="/usr/bin/mitmdump"
            ), mock.patch(
                "extra.mitmproxy_analyzer._port_is_listening", return_value=False
            ), mock.patch(
                "extra.mitmproxy_analyzer._live_capture",
                return_value=(False, "could not set device proxy via ADB: denied"),
            ):
                result = mitmproxy_analyzer.run(ctx)

        self.assertTrue(result.get("skipped"))
        self.assertEqual(result["tool"], "mitmproxy")
        self.assertTrue(
            any(f["rule_id"] == "MITM_PROXY_NOT_READY" for f in result["findings"])
        )
        self.assertIn("could not set device proxy", result["output"])

    def test_resolve_dump_dir_prefers_report_output(self):
        with mock.patch.dict(
            os.environ,
            {"ANDROSEC_MITM_OUT": "/tmp/mitm-out", "ANDROSEC_OUTPUT_DIR": "/tmp/scan-out"},
            clear=False,
        ):
            self.assertEqual(mitmproxy_analyzer.resolve_dump_dir(), "/tmp/mitm-out")
        env = {k: v for k, v in os.environ.items() if k != "ANDROSEC_MITM_OUT"}
        env["ANDROSEC_OUTPUT_DIR"] = "/tmp/scan-out-only"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(mitmproxy_analyzer.resolve_dump_dir(), "/tmp/scan-out-only")


class MitmproxyAddonsTests(unittest.TestCase):
    """Unit-test addon logic + analyzer parsing (no mitmdump required)."""

    def test_addon_scripts_exist(self):
        from extra.mitmproxy_addons import addon_script_paths, loader_script_path

        self.assertTrue(os.path.isfile(loader_script_path()))
        paths = addon_script_paths()
        self.assertEqual(len(paths), 4)
        for path in paths:
            self.assertTrue(os.path.isfile(path), path)

    def test_sensitive_data_detector(self):
        from extra.mitmproxy_addons.sensitive_data import analyze_flow

        findings = analyze_flow(
            {
                "method": "POST",
                "url": "https://api.lab/v1/token?api_key=xyz",
                "headers": {"X-Debug": "nope"},
                "request_body": "password=hunter2",
                "response_body": "",
            }
        )
        rules = {f["rule_id"] for f in findings}
        self.assertIn("MITM_SENSITIVE_BODY", rules)
        self.assertTrue(all(f.get("androsec") == "mitm_finding" for f in findings))
        self.assertTrue(any("password" in json.dumps(f) for f in findings))
        self.assertTrue(any("api_key" in json.dumps(f) or "api_key" in str(f.get("detail")) for f in findings))

    def test_cleartext_http_detector(self):
        from extra.mitmproxy_addons.cleartext_http import analyze_flow

        http_hits = analyze_flow(
            {"method": "GET", "url": "http://evil.lab/x", "headers": {}}
        )
        https_hits = analyze_flow(
            {"method": "GET", "url": "https://safe.lab/x", "headers": {}}
        )
        self.assertEqual(len(http_hits), 1)
        self.assertEqual(http_hits[0]["rule_id"], "MITM_CLEARTEXT_HTTP")
        self.assertEqual(https_hits, [])

    def test_api_endpoint_logger_unique(self):
        from extra.mitmproxy_addons.api_endpoint_logger import (
            analyze_flow,
            format_endpoint_report,
            summary_finding,
        )

        a = analyze_flow(
            {"method": "get", "url": "https://api.lab/v1/accounts", "headers": {}}
        )
        b = analyze_flow(
            {"method": "GET", "url": "https://api.lab/v1/accounts?x=1", "headers": {}}
        )
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["method"], "GET")
        self.assertEqual(a[0]["path"], "/v1/accounts")
        self.assertEqual(a[0]["host"], "api.lab")
        # Same method+host+path (query ignored in path parse)
        self.assertEqual(
            (a[0]["method"], a[0]["host"], a[0]["path"]),
            (b[0]["method"], b[0]["host"], b[0]["path"]),
        )
        report = format_endpoint_report(a)
        self.assertIn("GET", report)
        self.assertIn("api.lab", report)
        summary = summary_finding(a)
        self.assertEqual(summary["rule_id"], "MITM_TRAFFIC_SUMMARY")

    def test_auth_header_capture(self):
        from extra.mitmproxy_addons.auth_header_capture import analyze_flow

        findings = analyze_flow(
            {
                "method": "GET",
                "url": "https://api.lab/me",
                "headers": {
                    "Authorization": "Bearer abc",
                    "Cookie": "session=1",
                    "Accept": "application/json",
                },
            }
        )
        self.assertEqual(len(findings), 2)
        headers = {f["detail"]["header"].lower() for f in findings}
        self.assertEqual(headers, {"authorization", "cookie"})
        self.assertTrue(all(f["rule_id"] == "MITM_SENSITIVE_HEADER" for f in findings))

    def test_parse_addon_output_and_run_mixed_dump(self):
        with open(ADDON_FIXTURE, encoding="utf-8") as handle:
            raw = handle.read()
        flows = mitmproxy_analyzer.parse_mitm_dump(raw)
        self.assertEqual(len(flows), 1)
        findings, reports, endpoints = mitmproxy_analyzer.parse_addon_output(raw)
        rules = {f["rule_id"] for f in findings}
        self.assertIn("MITM_CLEARTEXT_HTTP", rules)
        self.assertIn("MITM_SENSITIVE_BODY", rules)
        self.assertIn("MITM_SENSITIVE_HEADER", rules)
        self.assertTrue(reports)
        self.assertEqual(len(endpoints), 1)

        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "com.android.insecurebankv2"
        with mock.patch.dict(os.environ, {"ANDROSEC_MITM_DUMP": ADDON_FIXTURE}):
            result = mitmproxy_analyzer.run(ctx)
        self.assertFalse(result.get("skipped"))
        out_rules = {f["rule_id"] for f in result["findings"]}
        self.assertIn("MITM_CLEARTEXT_HTTP", out_rules)
        self.assertIn("MITM_SENSITIVE_HEADER", out_rules)
        # Sensitive hits present → traffic summary should not dominate
        self.assertNotIn("MITM_TRAFFIC_SUMMARY", out_rules)
        self.assertIn("API endpoints", result["output"])

    def test_resolve_addon_loader(self):
        path = mitmproxy_analyzer.resolve_addon_loader()
        self.assertIsNotNone(path)
        self.assertTrue(path.endswith("loader.py"))
        self.assertTrue(os.path.isfile(path))

    def test_offline_dump_still_works_without_addon_lines(self):
        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "com.android.insecurebankv2"
        with mock.patch.dict(os.environ, {"ANDROSEC_MITM_DUMP": FIXTURE}):
            result = mitmproxy_analyzer.run(ctx)
        self.assertFalse(result.get("skipped"))
        rules = {f["rule_id"] for f in result["findings"]}
        self.assertIn("MITM_CLEARTEXT_HTTP", rules)


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
