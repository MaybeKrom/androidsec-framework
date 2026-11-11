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
        self.assertEqual(summary["score"], 25)
        self.assertEqual(summary["counts"]["Critical"], 1)

    def test_score_capping_at_100(self):
        # 10 critical findings would be 250 points, capped at 100
        findings = [{"severity": "Critical", "confidence": "High"} for _ in range(10)]
        summary = self.engine.compute(findings)
        self.assertEqual(summary["score"], 100)
        self.assertEqual(summary["level"], "CRITICAL")
        self.assertEqual(summary["counts"]["Critical"], 10)

    def test_risk_levels(self):
        # score == 0 -> PASS
        pass_summary = self.engine.compute([])
        self.assertEqual(pass_summary["level"], "PASS")

        # score 1-14 -> LOW (e.g. 1 Low = 1)
        low_summary = self.engine.compute([{"severity": "Low", "confidence": "High"}])
        self.assertEqual(low_summary["level"], "LOW")
        self.assertEqual(low_summary["score"], 1)

        # score 15-34 -> MEDIUM (e.g. 1 High (10) + 1 Medium (5) = 15)
        med_summary = self.engine.compute([
            {"severity": "High", "confidence": "High"},
            {"severity": "Medium", "confidence": "High"}
        ])
        self.assertEqual(med_summary["level"], "MEDIUM")
        self.assertEqual(med_summary["score"], 15)

        # score 35-59 -> HIGH (e.g. 4 High = 40)
        high_summary = self.engine.compute([{"severity": "High", "confidence": "High"} for _ in range(4)])
        self.assertEqual(high_summary["level"], "HIGH")
        self.assertEqual(high_summary["score"], 40)

        # score 60-100 -> CRITICAL (e.g. 3 Critical = 75)
        crit_summary = self.engine.compute([{"severity": "Critical", "confidence": "High"} for _ in range(3)])
        self.assertEqual(crit_summary["level"], "CRITICAL")
        self.assertEqual(crit_summary["score"], 75)


if __name__ == "__main__":
    unittest.main()
