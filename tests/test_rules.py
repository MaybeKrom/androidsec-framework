import json
import os
import unittest

from rules.owasp_mapper import OWASPMapper
from rules.rules_engine import RulesEngine

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRulesAndMapping(unittest.TestCase):
    def setUp(self):
        self.rules_path = os.path.join(BASE, "rules", "rules.json")
        self.mapping_path = os.path.join(BASE, "rules", "owasp_mapping.json")

    def test_rules_json_structure(self):
        self.assertTrue(os.path.exists(self.rules_path), "rules.json must exist")
        with open(self.rules_path, "r", encoding="utf-8") as f:
            rules = json.load(f)

        self.assertIsInstance(rules, dict)
        valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
        valid_confidences = {"High", "Medium", "Low"}

        for rule_id, rule_def in rules.items():
            self.assertIn("severity", rule_def, f"Rule {rule_id} missing 'severity'")
            self.assertIn(rule_def["severity"], valid_severities, f"Rule {rule_id} invalid severity: {rule_def['severity']}")
            self.assertIn("confidence", rule_def, f"Rule {rule_id} missing 'confidence'")
            self.assertIn(rule_def["confidence"], valid_confidences, f"Rule {rule_id} invalid confidence: {rule_def['confidence']}")
            self.assertIn("title", rule_def, f"Rule {rule_id} missing 'title'")
            self.assertIn("description", rule_def, f"Rule {rule_id} missing 'description'")
            self.assertIn("recommendation", rule_def, f"Rule {rule_id} missing 'recommendation'")

    def test_owasp_mapping_structure(self):
        self.assertTrue(os.path.exists(self.mapping_path), "owasp_mapping.json must exist")
        with open(self.mapping_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)

        self.assertIsInstance(mapping, dict)
        for rule_id, masvs_id in mapping.items():
            self.assertTrue(
                masvs_id.startswith("MASVS-"),
                f"Mapping for {rule_id} should start with 'MASVS-', got '{masvs_id}'"
            )

    def test_all_rules_have_owasp_mapping(self):
        with open(self.rules_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
        with open(self.mapping_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)

        missing = [r for r in rules if r not in mapping]
        self.assertEqual(missing, [], f"The following rules are missing from owasp_mapping.json: {missing}")

    def test_rules_engine_enrichment(self):
        re = RulesEngine(self.rules_path)
        raw = [{"rule_id": "MANIFEST_DEBUGGABLE", "evidence": "debuggable=true"}]
        enriched = re.enrich(raw)

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["severity"], "High")
        self.assertEqual(enriched[0]["confidence"], "High")
        self.assertEqual(enriched[0]["title"], "Application is debuggable")

    def test_owasp_mapper(self):
        om = OWASPMapper(self.mapping_path)
        findings = [{"rule_id": "MANIFEST_DEBUGGABLE"}]
        mapped = om.apply(findings)

        self.assertEqual(len(mapped), 1)
        self.assertEqual(mapped[0]["masvs"], "MASVS-RESILIENCE-2")


if __name__ == "__main__":
    unittest.main()
