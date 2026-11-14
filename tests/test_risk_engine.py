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

    def test_high_soft_cap_and_weights(self):
        # High weight=7; first 3 full, 4th half → 7*3 + 3.5 = 24.5 → 24 or 25
        findings = [{"severity": "High", "confidence": "High"} for _ in range(4)]
        summary = self.engine.compute(findings)
        self.assertEqual(summary["score"], 24)
        self.assertLess(summary["score"], 7 * 4)

    def test_ibv2_style_stack_does_not_auto_saturate(self):
        # One Critical + two High + many Medium must stay under 100 after soft caps.
        findings = (
            [{"severity": "Critical", "confidence": "High"}]
            + [{"severity": "High", "confidence": "High"} for _ in range(2)]
            + [{"severity": "Medium", "confidence": "High"} for _ in range(13)]
            + [{"severity": "Info", "confidence": "High"} for _ in range(20)]
        )
        summary = self.engine.compute(findings)
        self.assertLess(summary["score"], 100)
        self.assertGreaterEqual(summary["score"], 40)

    def test_risk_levels(self):
        pass_summary = self.engine.compute([])
        self.assertEqual(pass_summary["level"], "PASS")

        low_summary = self.engine.compute([{"severity": "Low", "confidence": "High"}])
        self.assertEqual(low_summary["level"], "LOW")
        self.assertEqual(low_summary["score"], 1)

        # 3 High (7+7+7=21) → MEDIUM
        med_summary = self.engine.compute([
            {"severity": "High", "confidence": "High"},
            {"severity": "High", "confidence": "High"},
            {"severity": "High", "confidence": "High"},
        ])
        self.assertEqual(med_summary["level"], "MEDIUM")
        self.assertEqual(med_summary["score"], 21)

        # 5 High = 7*3 + 3.5*2 = 28 → MEDIUM
        high_summary = self.engine.compute(
            [{"severity": "High", "confidence": "High"} for _ in range(5)]
        )
        self.assertEqual(high_summary["level"], "MEDIUM")
        self.assertEqual(high_summary["score"], 28)

        # 4 Critical with soft-cap: 20+20+10+10 = 60 → CRITICAL
        crit_summary = self.engine.compute(
            [{"severity": "Critical", "confidence": "High"} for _ in range(4)]
        )
        self.assertEqual(crit_summary["level"], "CRITICAL")
        self.assertEqual(crit_summary["score"], 60)


if __name__ == "__main__":
    unittest.main()
