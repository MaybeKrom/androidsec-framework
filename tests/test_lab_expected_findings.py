"""Smoke-load the lab expected-findings benchmark fixture."""

import json
import os
import unittest


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "lab_expected_findings.json")


class LabExpectedFindingsTests(unittest.TestCase):
    def test_fixture_shape(self):
        with open(FIXTURE, encoding="utf-8") as f:
            data = json.load(f)
        apps = data["apps"]
        for name in ("DIVA", "InsecureBankv2", "AndroGoat", "UnCrackable"):
            self.assertIn(name, apps)
            entry = apps[name]
            self.assertTrue(entry.get("must_have") or entry.get("package_prefixes"))
            self.assertIsInstance(entry.get("must_not", []), list)

    def test_androgoat_must_not_includes_hostname_fp(self):
        with open(FIXTURE, encoding="utf-8") as f:
            data = json.load(f)
        must_not = data["apps"]["AndroGoat"]["must_not"]
        self.assertIn("CODE_HOSTNAME_VERIFIER", must_not)
        self.assertIn("SSL_PINNING_BYPASS_CONFLICT", must_not)


if __name__ == "__main__":
    unittest.main()
