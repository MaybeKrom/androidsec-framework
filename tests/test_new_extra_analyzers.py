import unittest
from unittest import mock

from rules.consolidate import consolidate_findings
from rules.rules_engine import RulesEngine
from rules.owasp_mapper import OWASPMapper
import main as scan_main
from extra import (
    lab_challenge_mapper,
    finding_correlator,
    sql_injection_scanner,
    crypto_key_analyzer,
    ssl_pinning_analyzer,
    intent_abuse_analyzer,
    native_security_analyzer,
    sbom_dependency_scanner,
)


class NewExtraAnalyzerTests(unittest.TestCase):
    def test_all_analyzer_modules_importable(self):
        for tool_id, mod_path, _desc in scan_main.ANALYZERS:
            mod = __import__(mod_path, fromlist=["run"])
            self.assertTrue(hasattr(mod, "run"), tool_id)

    def test_lab_mapper_diva(self):
        ctx = mock.Mock()
        ctx.apk.get_package.return_value = "jakhar.aseem.diva"
        result = lab_challenge_mapper.run(ctx)
        self.assertFalse(result.get("skipped"))
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("LAB_APP_DETECTED", rules)
        self.assertIn("LAB_CHALLENGE", rules)

    def test_new_rules_enrich(self):
        engine = RulesEngine("rules/rules.json")
        mapper = OWASPMapper("rules/owasp_mapping.json")
        raw = [
            {"rule_id": "SQL_RAW_QUERY_CONCAT", "evidence": "rawQuery("},
            {"rule_id": "CORRELATED_WEBVIEW_EXPORT", "evidence": "x"},
            {"rule_id": "CRYPTO_HARDCODED_KEY", "evidence": "key=abc"},
        ]
        enriched = mapper.apply(engine.enrich(raw))
        self.assertEqual(enriched[0]["severity"], "High")
        self.assertTrue(str(enriched[1]["masvs"]).startswith("MASVS-"))

    def test_cleartext_equivalent_collapse(self):
        out = consolidate_findings([
            {"rule_id": "MANIFEST_CLEARTEXT", "evidence": "a"},
            {"rule_id": "NETWORK_CLEARTEXT_ALLOWED", "evidence": "b"},
        ])
        rules = [f["rule_id"] for f in out]
        self.assertIn("MANIFEST_CLEARTEXT", rules)
        self.assertNotIn("NETWORK_CLEARTEXT_ALLOWED", rules)


if __name__ == "__main__":
    unittest.main()
