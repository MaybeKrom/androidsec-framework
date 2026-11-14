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

    def test_component_beats_intent_unprotected_same_surface(self):
        findings = [
            {
                "rule_id": "COMPONENT_ACTIVITY",
                "evidence": "com.android.insecurebankv2.PostLogin (permission=none)",
                "severity": "Medium",
            },
            {
                "rule_id": "INTENT_EXPORTED_UNPROTECTED",
                "evidence": "activity:com.android.insecurebankv2.PostLogin actions=[]",
                "severity": "Medium",
            },
            {
                "rule_id": "INTENT_ACTIVITY_POC",
                "evidence": "adb shell am start -n com.android.insecurebankv2/com.android.insecurebankv2.PostLogin",
                "severity": "Info",
            },
            {
                "rule_id": "COMPONENT_RECEIVER",
                "evidence": "com.android.insecurebankv2.MyBroadCastReceiver (permission=none)",
                "severity": "Medium",
            },
            {
                "rule_id": "INTENT_EXPORTED_UNPROTECTED",
                "evidence": "receiver:com.android.insecurebankv2.MyBroadCastReceiver actions=['theBroadcast']",
                "severity": "Medium",
            },
        ]
        out = consolidate_findings(findings)
        rules = [f["rule_id"] for f in out]
        self.assertEqual(rules.count("COMPONENT_ACTIVITY"), 1)
        self.assertEqual(rules.count("COMPONENT_RECEIVER"), 1)
        self.assertNotIn("INTENT_EXPORTED_UNPROTECTED", rules)
        self.assertIn("INTENT_ACTIVITY_POC", rules)

    def test_crypto_ecb_double_rule_collapses(self):
        out = consolidate_findings([
            {"rule_id": "CODE_WEAK_CRYPTO_ECB", "evidence": "AES/ECB/PKCS5Padding", "severity": "High"},
            {"rule_id": "CRYPTO_WEAK_TRANSFORM", "evidence": "AES/ECB/PKCS5Padding", "severity": "High"},
            {"rule_id": "CRYPTO_TRANSFORM_FOUND", "evidence": "AES/CBC/PKCS5Padding", "severity": "Info"},
        ])
        rules = [f["rule_id"] for f in out]
        self.assertIn("CODE_WEAK_CRYPTO_ECB", rules)
        self.assertNotIn("CRYPTO_WEAK_TRANSFORM", rules)
        self.assertIn("CRYPTO_TRANSFORM_FOUND", rules)

    def test_intent_kept_when_no_component_row(self):
        out = consolidate_findings([
            {
                "rule_id": "INTENT_EXPORTED_UNPROTECTED",
                "evidence": "service:com.example.OnlyInIntent actions=[]",
                "severity": "Medium",
            },
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["rule_id"], "INTENT_EXPORTED_UNPROTECTED")


if __name__ == "__main__":
    unittest.main()

