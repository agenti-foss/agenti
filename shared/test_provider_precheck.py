"""Launch refuses missing provider configuration before allocating a slot."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from run_coverage import why_refused
import preflight


class ProviderPrecheck(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.org = Path(self.folder.name) / "org"
        self.org.mkdir()
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.policy = {"allowed_models": ["openai:*", "local:*", "anthropic:*"],
                       "model_prices": {"openai:test": [2, 12]}}
        self.save()

    def save(self):
        record = {"engagement_id": "TEST", "client": "Example", "authorizing_party": "Admin",
                  "authorizing_title": "Owner", "authorization_ref": "TEST",
                  "valid_from": "2020-01-01", "valid_until": "2099-12-31",
                  "emergency_contact": "admin@example.com", "notes": "",
                  "scope": {"cidr": {"in_scope": ["192.0.2.0/24"], "out_of_scope": []},
                            "domain": {"in_scope": ["example.com"], "out_of_scope": []}},
                  "policy": self.policy}
        (self.org / "engagement.json").write_text(json.dumps(record))

    def secret(self, relative, text):
        file = self.org / relative / "secrets.env"
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        file.chmod(0o600)

    def reasons(self, model):
        return why_refused(self.org, "cracker", "files", "", model, "tester")

    def test_cloud_key_and_price_are_required_independently(self):
        self.assertIn("API key", " ".join(self.reasons("openai:test")))
        with patch.dict(os.environ, {"OPENAI_API_KEY": "launching-shell-only"}):
            self.assertIn("API key", " ".join(self.reasons("openai:test")))
        self.secret(".", "OPENAI_API_KEY=fixture\n")
        self.assertEqual(self.reasons("openai:test"), [])
        self.assertIn("--model-price", " ".join(self.reasons("openai:unpriced")))

    def test_user_claude_key_does_not_hide_org_openai_key(self):
        self.secret("users/tester", "ANTHROPIC_API_KEY=fixture\n")
        self.secret(".", "OPENAI_API_KEY=fixture\n")
        self.assertEqual(self.reasons("openai:test"), [])
        self.assertEqual(self.reasons("sonnet"), [])

    def test_local_needs_address_but_no_key_or_price(self):
        self.assertIn("--base-url", " ".join(self.reasons("local:test")))
        for address in ("file:///tmp/model", "http://host:99999/v1", "http://user:password@host/v1"):
            self.secret(".", f"LOCAL_LLM_BASE_URL={address}\n")
            self.assertIn("--base-url", " ".join(self.reasons("local:test")))
        self.secret(".", "LOCAL_LLM_BASE_URL=http://localhost:11434/v1\n")
        self.assertEqual(self.reasons("local:test"), [])

    def test_preflight_uses_the_selected_provider(self):
        slot = Path(self.folder.name) / "slot"
        slot.mkdir()
        with patch.object(preflight, "DATA_ROOT", slot), patch.object(preflight, "SECRETS_CANDIDATES", []):
            for model, environment, expected in (
                ("openai:test", {"OPENAI_API_KEY": "fixture"}, True),
                ("openai:test", {"ANTHROPIC_API_KEY": "fixture"}, False),
                ("local:test", {"LOCAL_LLM_BASE_URL": "http://localhost:11434/v1"}, True),
                ("sonnet", {"ANTHROPIC_API_KEY": "fixture"}, True),
            ):
                (slot / "run-config.json").write_text(json.dumps({"model": model}))
                with patch.dict(os.environ, environment, clear=True):
                    preflight.results.clear()
                    preflight.check_secrets()
                    self.assertEqual(preflight.results[-1][0], expected, model)
            (slot / "run-config.json").write_text(json.dumps({"model": "openai:test"}))
            preflight.results.clear()
            preflight.check_claude_code()
            self.assertEqual(preflight.results[-1], (True, "claude-code", "not needed for this provider"))

    def test_egress_checks_the_selected_endpoint_through_relay(self):
        slot = Path(self.folder.name) / "slot"
        slot.mkdir()
        with patch.object(preflight, "DATA_ROOT", slot), \
                patch.object(preflight, "_connect_api") as connect, \
                patch.object(preflight.ssl, "create_default_context"):
            for model, host, port, address in (
                ("openai:test", "api.openai.com", 443, ""),
                ("sonnet", "api.anthropic.com", 443, ""),
                ("local:test", "localhost", 11434, "http://localhost:11434/v1"),
            ):
                (slot / "run-config.json").write_text(json.dumps({"model": model}))
                with patch.dict(os.environ, {"AGENTI_RELAY": "http://127.0.0.1:8429",
                                             "LOCAL_LLM_BASE_URL": address}, clear=True):
                    preflight.results.clear()
                    preflight.check_egress()
                    self.assertTrue(preflight.results[-1][0], preflight.results[-1])
                    connect.assert_called_with("http://127.0.0.1:8429", host, port)


if __name__ == "__main__":
    unittest.main()
