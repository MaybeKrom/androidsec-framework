import unittest

from engine.risk_engine import RiskEngine


class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_empty_findings(self):
        summary = self.engine.compute([])
        self.assertEqual(summary["score"], 0)
        self.assertEqual(summary["level"], "PASS")
        self.assertEqual(summary["counts"], {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0})

    def test_single_finding_scoring(self):
        critical_finding = [{"severity": "Critical", "confidence": "High"}]
        summary = self.engine.compute(critical_finding)
        self.assertEqual(summary["score"], 20)
        self.assertEqual(summary["counts"]["Critical"], 1)

    def test_aws_format_only_does_not_saturate(self):
        # Medium-confidence Critical (format-only AWS) + correlator Info must stay < 100 alone.
        findings = [
            {"severity": "Critical", "confidence": "Medium"},
            {"severity": "Info", "confidence": "Medium"},
            {"severity": "Info", "confidence": "Medium"},
        ]
        summary = self.engine.compute(findings)
        self.assertLess(summary["score"], 40)
        self.assertNotEqual(summary["level"], "CRITICAL")

    def test_score_capping_at_100(self):
        findings = [{"severity": "Critical", "confidence": "High"} for _ in range(10)]
        summary = self.engine.compute(findings)
        self.assertEqual(summary["score"], 100)
        self.assertEqual(summary["level"], "CRITICAL")
        self.assertEqual(summary["counts"]["Critical"], 10)

    def test_critical_soft_cap(self):
        # First two Critical @20, further at half → 20+20+10=50
        findings = [{"severity": "Critical", "confidence": "High"} for _ in range(3)]
        summary = self.engine.compute(findings)
        self.assertEqual(summary["score"], 50)

    def test_risk_levels(self):
        pass_summary = self.engine.compute([])
        self.assertEqual(pass_summary["level"], "PASS")

        low_summary = self.engine.compute([{"severity": "Low", "confidence": "High"}])
        self.assertEqual(low_summary["level"], "LOW")
        self.assertEqual(low_summary["score"], 1)

        # 2 High (8+8=16) → MEDIUM
        med_summary = self.engine.compute([
            {"severity": "High", "confidence": "High"},
            {"severity": "High", "confidence": "High"},
        ])
        self.assertEqual(med_summary["level"], "MEDIUM")
        self.assertEqual(med_summary["score"], 16)

        # 5 High = 40 → HIGH
        high_summary = self.engine.compute(
            [{"severity": "High", "confidence": "High"} for _ in range(5)]
        )
        self.assertEqual(high_summary["level"], "HIGH")
        self.assertEqual(high_summary["score"], 40)

        # 4 Critical with soft-cap: 20+20+10+10 = 60 → CRITICAL
        crit_summary = self.engine.compute(
            [{"severity": "Critical", "confidence": "High"} for _ in range(4)]
        )
        self.assertEqual(crit_summary["level"], "CRITICAL")
        self.assertEqual(crit_summary["score"], 60)


if __name__ == "__main__":
    unittest.main()
