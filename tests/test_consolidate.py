import unittest

from rules.consolidate import consolidate_findings


class ConsolidateTests(unittest.TestCase):
    def test_collapses_hostname_verifier_dupes(self):
        findings = [
            {"rule_id": "CODE_HOSTNAME_VERIFIER", "evidence": "a", "severity": "High"},
            {"rule_id": "CODE_HOSTNAME_VERIFIER", "evidence": "b", "severity": "High"},
            {"rule_id": "SECRET_AWS_KEY", "evidence": "AKIA1", "severity": "Critical"},
            {"rule_id": "SECRET_AWS_KEY", "evidence": "AKIA2", "severity": "Critical"},
        ]
        out = consolidate_findings(findings)
        rules = [f["rule_id"] for f in out]
        self.assertEqual(rules.count("CODE_HOSTNAME_VERIFIER"), 1)
        self.assertEqual(rules.count("SECRET_AWS_KEY"), 2)
        self.assertIn("collapsed", out[0]["evidence"].lower())


if __name__ == "__main__":
    unittest.main()
