"""Finding review: load a report row, require acknowledgment, and do not store the key."""

import json
import os
import tempfile
import unittest

from webapp.review import (
    PROVIDERS,
    ReviewError,
    build_provider_request,
    load_finding,
    response_text,
    review_prompt,
)


def _payload():
    return {
        "metadata": {
            "package": "owasp.mstg.uncrackable1",
            "app_name": "Uncrackable1",
            "version_name": "1.0",
        },
        "summary": {"level": "LOW", "score": 10},
        "findings": [
            {
                "severity": "Info",
                "rule_id": "NOTE",
                "title": "No mapping",
                "evidence": "n/a",
                "recommendation": "None",
                "masvs": "N/A",
            },
            {
                "severity": "High",
                "rule_id": "EXPORTED",
                "title": "Exported component",
                "evidence": "activity",
                "recommendation": "Set exported false",
                "masvs": "MASVS-PLATFORM-1",
            },
        ],
    }


class LoaderTests(unittest.TestCase):
    def test_index_follows_the_report_table_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            name = "security_report_20261111_120000.html"
            with open(os.path.join(tmp, name[:-5] + ".json"), "w", encoding="utf-8") as handle:
                json.dump(_payload(), handle)
            loaded = load_finding(tmp, name, 0)
        self.assertEqual(loaded["finding"]["rule_id"], "EXPORTED")
        prompt = review_prompt(loaded)
        self.assertIn("King Saud University", prompt)
        self.assertIn("Do not write exploit code", prompt)
        self.assertIn("Exported component", prompt)
        self.assertIn("activity", prompt)

    def test_rejects_a_path_and_a_bad_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            name = "security_report_20261111_120000.html"
            with open(os.path.join(tmp, name[:-5] + ".json"), "w", encoding="utf-8") as handle:
                json.dump(_payload(), handle)
            with self.assertRaises(LookupError):
                load_finding(tmp, "../" + name, 0)
            with self.assertRaises(LookupError):
                load_finding(tmp, name, 5)

    def test_response_text_reads_the_responses_payload(self):
        payload = {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Hi, im fully ready"}],
                }
            ]
        }
        self.assertEqual(response_text(payload), "Hi, im fully ready")
        self.assertEqual(response_text({"output_text": "plain"}), "plain")

    def test_response_text_reads_chat_anthropic_and_gemini(self):
        chat = {"choices": [{"message": {"role": "assistant", "content": "Hi, im fully ready"}}]}
        parts = {"choices": [{"message": {"content": [{"type": "text", "text": "from parts"}]}}]}
        claude = {"content": [{"type": "text", "text": "Hi, im fully ready"}], "role": "assistant"}
        gemini = {"candidates": [{"content": {"parts": [{"text": "Hi, im fully ready"}]}}]}
        self.assertEqual(response_text(chat), "Hi, im fully ready")
        self.assertEqual(response_text(parts), "from parts")
        self.assertEqual(response_text(claude), "Hi, im fully ready")
        self.assertEqual(response_text(gemini), "Hi, im fully ready")


class ProviderRequestTests(unittest.TestCase):
    KEY = "super-secret-key-xyz"

    def _body(self, provider, model="", base_url=""):
        url, headers, raw = build_provider_request(provider, model, base_url, self.KEY, "Hello")
        self.assertNotIn(self.KEY, url)
        return url, headers, json.loads(raw.decode("utf-8"))

    def test_openai_chat_shape_uses_the_typed_model(self):
        url, headers, body = self._body("openai", "my-model")
        self.assertEqual(url, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(headers["Authorization"], f"Bearer {self.KEY}")
        self.assertEqual(body["model"], "my-model")
        self.assertEqual(body["messages"], [{"role": "user", "content": "Hello"}])

    def test_anthropic_uses_its_own_header_and_body(self):
        url, headers, body = self._body("anthropic")
        self.assertEqual(url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(headers["x-api-key"], self.KEY)
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(body["model"], PROVIDERS["anthropic"]["model"])
        self.assertEqual(body["max_tokens"], 4096)
        self.assertEqual(body["messages"][0]["content"], "Hello")

    def test_gemini_keeps_the_key_out_of_the_url(self):
        url, headers, body = self._body("gemini", "gemini-3.5-flash")
        self.assertTrue(url.endswith("/models/gemini-3.5-flash:generateContent"))
        self.assertNotIn("key=", url)
        self.assertEqual(headers["x-goog-api-key"], self.KEY)
        self.assertNotIn("Authorization", headers)
        self.assertEqual(body["contents"][0]["parts"][0]["text"], "Hello")

    def test_openrouter_deepseek_and_xai_are_chat_calls(self):
        openrouter, _, openrouter_body = self._body("openrouter")
        deepseek, _, _ = self._body("deepseek")
        xai, _, xai_body = self._body("xai")
        self.assertEqual(openrouter, "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(openrouter_body["model"], "openai/gpt-5.2")
        self.assertEqual(deepseek, "https://api.deepseek.com/chat/completions")
        self.assertEqual(xai, "https://api.x.ai/v1/chat/completions")
        self.assertNotIn("/responses", xai)
        self.assertEqual(xai_body["model"], "grok-4.7")

    def test_custom_address_is_joined_and_private_targets_are_refused(self):
        url, headers, body = self._body("custom", "local-model", "http://127.0.0.1:11434/v1")
        self.assertEqual(url, "http://127.0.0.1:11434/v1/chat/completions")
        self.assertEqual(headers["Authorization"], f"Bearer {self.KEY}")
        self.assertEqual(body["model"], "local-model")
        kept, _, _ = self._body("custom", "m", "https://example.com/v1/chat/completions")
        self.assertEqual(kept, "https://example.com/v1/chat/completions")
        refused = [
            "http://10.0.0.8/v1",
            "http://169.254.169.254/",
            "https://user:pass@example.com/v1",
            "https://example.com/v1?token=secret",
            "file:///etc/passwd",
            "http://example.com/v1",
        ]
        for base in refused:
            with self.assertRaises(ReviewError):
                build_provider_request("custom", "m", base, self.KEY, "Hello")

    def test_unknown_provider_and_bad_model_are_refused(self):
        with self.assertRaises(ReviewError):
            build_provider_request("nope", "m", "", self.KEY, "Hello")
        with self.assertRaises(ReviewError):
            build_provider_request("gemini", "models/gemini", "", self.KEY, "Hello")
        with self.assertRaises(ReviewError):
            build_provider_request("openai", "bad model", "", self.KEY, "Hello")
        with self.assertRaises(ReviewError):
            build_provider_request("openai", "gpt", "", "key\nwith-break", "Hello")


class GateTests(unittest.TestCase):
    def setUp(self):
        import webapp.app as web
        import webapp.review as review

        self.review = review
        self.client = web.app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "reviews.sqlite")
        name = "security_report_20261111_120000.html"
        with open(os.path.join(self.tmp.name, name[:-5] + ".json"), "w", encoding="utf-8") as handle:
            json.dump(_payload(), handle)
        self.name = name
        self.saved = {
            "report_dir": review.REPORT_DIR,
            "db": review.DB_PATH,
            "live": review.is_live_report,
            "ask": review.ask_model,
        }
        review.REPORT_DIR = self.tmp.name
        review.DB_PATH = self.db
        review.is_live_report = lambda report_name: report_name == name
        self.calls = []

        def fake(api_key, prompt, timeout, provider="openai", model="", base_url=""):
            self.calls.append((api_key, prompt, provider, model, base_url))
            if "exactly this sentence" in prompt:
                return "Hi, im fully ready"
            return "The component is exported. Set android:exported to false."

        review.ask_model = fake

    def tearDown(self):
        self.review.REPORT_DIR = self.saved["report_dir"]
        self.review.DB_PATH = self.saved["db"]
        self.review.is_live_report = self.saved["live"]
        self.review.ask_model = self.saved["ask"]
        self.tmp.cleanup()

    def _post(self, **extra):
        data = {
            "report": self.name,
            "i": "0",
            "provider": "xai",
            "api_key": "super-secret-key-xyz",
            "responsibility": "yes",
            "key_not_stored": "yes",
        }
        data.update(extra)
        data = {key: value for key, value in data.items() if value is not None}
        return self.client.post("/review", data=data)

    def test_boxes_are_required_before_any_call(self):
        page = self.client.get(f"/review?report={self.name}&i=0")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"I confirm that my API key is not stored.", page.data)
        self.assertIn(b"OpenAI", page.data)
        self.assertIn(b"Anthropic (Claude)", page.data)
        self.assertIn(b"Google Gemini", page.data)
        self.assertIn(b"OpenRouter", page.data)
        self.assertIn(b"DeepSeek", page.data)
        self.assertIn(b'id="base-url-field" hidden', page.data)
        blocked = self._post(responsibility=None, key_not_stored=None)
        self.assertEqual(blocked.status_code, 200)
        self.assertIn(b"Check both acknowledgment boxes", blocked.data)
        self.assertEqual(self.calls, [])

    def test_a_reply_that_is_not_ready_does_not_send_the_finding(self):
        def not_ready(api_key, prompt, timeout, **_extra):
            self.calls.append(prompt)
            return "Hello"

        self.review.ask_model = not_ready
        page = self._post()
        self.assertIn(b"finding was not sent", page.data)
        self.assertEqual(len(self.calls), 1)
        import sqlite3
        connection = sqlite3.connect(self.db)
        try:
            count = connection.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 0)

    def test_a_ready_reply_saves_the_review_without_the_key(self):
        page = self._post()
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Hi, im fully ready", page.data)
        self.assertIn(b"Set android:exported to false.", page.data)
        self.assertNotIn(b"super-secret-key-xyz", page.data)
        with open(self.db, "rb") as handle:
            stored = handle.read()
        self.assertNotIn(b"super-secret-key-xyz", stored)
        self.assertEqual(len(self.calls), 2)

        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("the saved review must not call the model")

        self.review.ask_model = fail_if_called
        again = self.client.get(f"/review?report={self.name}&i=0")
        self.assertIn(b"Set android:exported to false.", again.data)
        self.assertIn(b"Saved", again.data)

    def test_openai_is_accepted_and_an_unknown_provider_is_not_called(self):
        page = self._post(provider="openai", model="gpt-test")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Set android:exported to false.", page.data)
        self.assertEqual(self.calls[0][2], "openai")
        self.assertEqual(self.calls[0][3], "gpt-test")
        self.calls.clear()
        refused = self._post(provider="nope")
        self.assertIn(b"Choose a provider.", refused.data)
        self.assertEqual(self.calls, [])

    def test_unknown_report_is_not_found(self):
        missing = self.client.get("/review?report=security_report_20261111_120000.html&i=9")
        self.assertEqual(missing.status_code, 404)
        escaped = self.client.get("/review?report=../../etc/passwd&i=0")
        self.assertEqual(escaped.status_code, 404)


if __name__ == "__main__":
    unittest.main()
