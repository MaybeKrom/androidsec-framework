"""Regression tests for library / keyword / logcat / consolidate precision fixes."""

import unittest
from unittest import mock

from analyzers import static_code_scanner, log_analyzer, secret_detector
from extra import ssl_pinning_analyzer
from rules.consolidate import consolidate_findings
from webapp import exploit_grounding as g


class _FakeDex:
    def __init__(self, strings):
        self._strings = strings

    def get_strings(self):
        return self._strings


class _FakeCtx:
    def __init__(self, strings, package="owasp.sat.agoat"):
        self.dex = [_FakeDex(strings)]
        self.zip = mock.Mock()
        self.zip.namelist.return_value = []
        self.apk = mock.Mock()
        self.apk.get_package.return_value = package

    def get_manifest_root(self):
        return None


class StaticCodePrecisionTests(unittest.TestCase):
    def test_rejects_hostname_verifier_type_descriptor(self):
        ctx = _FakeCtx(["()Ljavax/net/ssl/HostnameVerifier;", "Lokhttp3/internal/http/BridgeInterceptor;"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("CODE_HOSTNAME_VERIFIER", rules)

    def test_accepts_allow_all_hostname_verifier(self):
        ctx = _FakeCtx(["ALLOW_ALL_HOSTNAME_VERIFIER used in LoginActivity"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("CODE_HOSTNAME_VERIFIER", rules)

    def test_rejects_bare_check_server_trusted(self):
        ctx = _FakeCtx(["checkServerTrusted", "Lokhttp3/OkHttpClient;"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("CODE_TRUST_ALL_CERTS", rules)

    def test_rejects_bare_util_random_descriptor(self):
        ctx = _FakeCtx(["Ljava/util/Random;"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("CODE_INSECURE_RANDOM", rules)

    def test_xposed_not_matching_exposed_dropdown(self):
        ctx = _FakeCtx(["ExposedDropdownMenuBox", "androidx.compose.material3.ExposedDropdownMenu"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("RESILIENCE_XPOSED_CHECK_PRESENT", rules)

    def test_frida_word_bound_not_tld_noise(self):
        # kotlinx / TLD-style noise should not trip Frida without a real token.
        ctx = _FakeCtx(["kotlinx.coroutines.flow", "example.fridakafka.notreal"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        # bare substring "frida" inside a longer token without word boundary — pattern uses \bfrida\b
        self.assertNotIn("RESILIENCE_FRIDA_CHECK_PRESENT", rules)

    def test_frida_server_still_detected(self):
        ctx = _FakeCtx(["looking for frida-server on device"])
        result = static_code_scanner.run(ctx)
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("RESILIENCE_FRIDA_CHECK_PRESENT", rules)


class SslPinningPrecisionTests(unittest.TestCase):
    def test_no_conflict_from_library_check_server_trusted(self):
        with mock.patch("extra.ssl_pinning_analyzer.iter_dex_strings", return_value=[
            "okhttp3.CertificatePinner",
            "checkServerTrusted",
        ]), mock.patch("extra.ssl_pinning_analyzer.zip_text_files", return_value=[]):
            result = ssl_pinning_analyzer.run(mock.Mock())
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SSL_PINNING_OKHTTP", rules)
        self.assertNotIn("SSL_TRUST_ALL", rules)
        self.assertNotIn("SSL_PINNING_BYPASS_CONFLICT", rules)

    def test_conflict_when_app_local_trust_all(self):
        with mock.patch("extra.ssl_pinning_analyzer.iter_dex_strings", return_value=[
            "CertificatePinner",
            "TrustAllCerts implemented in AppTls",
        ]), mock.patch("extra.ssl_pinning_analyzer.zip_text_files", return_value=[]):
            result = ssl_pinning_analyzer.run(mock.Mock())
        rules = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SSL_TRUST_ALL", rules)
        self.assertIn("SSL_PINNING_BYPASS_CONFLICT", rules)


class LogAnalyzerPrecisionTests(unittest.TestCase):
    def test_blocks_accessibility_dumper_password_fields(self):
        dump = (
            "I/AccessibilityNodeInfoDumper(1234): password=true; text=secret\n"
            "I/MyApp(5678): password=realuserpass\n"
        )
        with mock.patch("analyzers.log_analyzer._device_ready", return_value=(True, "")), \
             mock.patch("analyzers.log_analyzer._fetch_logcat", return_value=(dump, "test")):
            ctx = _FakeCtx([])
            result = log_analyzer.run(ctx)
        evidences = " ".join(f["evidence"] for f in result["findings"])
        self.assertNotIn("AccessibilityNodeInfoDumper", evidences)
        self.assertIn("password=realuserpass", evidences)


class ConsolidatePrecisionTests(unittest.TestCase):
    def test_provider_equivalents_collapse(self):
        out = consolidate_findings([
            {"rule_id": "COMPONENT_PROVIDER", "evidence": "NotesProvider"},
            {"rule_id": "COMPONENT_PROVIDER_AUTHORITY", "evidence": "content://x"},
            {"rule_id": "INTENT_EXPORTED_PROVIDER", "evidence": "NotesProvider"},
        ])
        rules = [f["rule_id"] for f in out]
        self.assertEqual(rules.count("COMPONENT_PROVIDER"), 1)
        self.assertNotIn("COMPONENT_PROVIDER_AUTHORITY", rules)
        self.assertNotIn("INTENT_EXPORTED_PROVIDER", rules)


class SecretAnnotateTests(unittest.TestCase):
    def test_lab_placeholder_annotated(self):
        text = secret_detector._annotate_secret("SECRET_AWS_KEY", "AKIAIOSFODNN7EXAMPLE")
        self.assertIn("placeholder", text.lower())


class ExploitGroundingPrecisionTests(unittest.TestCase):
    def test_hostname_verifier_is_network_tls(self):
        finding = {"rule_id": "CODE_HOSTNAME_VERIFIER", "evidence": "ALLOW_ALL_HOSTNAME_VERIFIER"}
        self.assertEqual(g.classify_finding(finding), "network_tls")

    def test_provider_outranks_hostname_verifier(self):
        provider = {"rule_id": "COMPONENT_PROVIDER", "severity": "High", "evidence": "content://x"}
        host = {"rule_id": "CODE_HOSTNAME_VERIFIER", "severity": "High", "evidence": "ALLOW_ALL"}
        self.assertGreater(g.exploit_priority(provider), g.exploit_priority(host))

    def test_jvm_descriptor_not_proof_token(self):
        finding = {
            "rule_id": "CODE_HOSTNAME_VERIFIER",
            "evidence": "()Ljavax/net/ssl/HostnameVerifier;  (+15 similar matches collapsed)",
        }
        tokens = g.extract_proof_tokens(finding, "owasp.sat.agoat")
        joined = " ".join(tokens)
        self.assertNotIn("Ljavax/net/ssl/HostnameVerifier", joined)

    def test_logging_baseline_avoids_bare_key(self):
        loaded = {
            "finding": {"rule_id": "LOG_SENSITIVE_PASSWORD", "evidence": "password=x"},
            "metadata": {"package": "owasp.sat.agoat"},
        }
        steps = g.finding_baseline_steps(loaded)
        joined = " ".join(s["command"] for s in steps)
        self.assertIn("password=", joined)
        self.assertNotRegex(joined, r"secret\|password\|key\|token")


if __name__ == "__main__":
    unittest.main()
