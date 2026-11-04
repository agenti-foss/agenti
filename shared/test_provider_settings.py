"""Provider views never expose keys; relay edits preserve existing authority."""
import tempfile
import unittest
import os
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

import provider_settings as ps
import model_registry as mr
from agent_runtime import read_secrets
from egress_relay import DEFAULT_ALLOW, allow_endpoint


class ProviderSettings(unittest.TestCase):
    def test_readiness_and_per_key_tiers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for relative, text in (("org/users/alice", "ANTHROPIC_API_KEY=user\n"),
                                   ("shared", "OPENAI_API_KEY=shared\nLOCAL_LLM_BASE_URL=http://model.example.com:11434/private-token/v1\n")):
                file = root / relative / "secrets.env"
                file.parent.mkdir(parents=True)
                file.write_text(text)
                file.chmod(0o600)
            view = ps.status(root, "alice")
            self.assertTrue(all(info["ready"] for info in view.values()))
            self.assertNotIn("shared", str(view))
            self.assertNotIn("private-token", str(view))
            self.assertEqual(ps.settings(root, "alice")["OPENAI_API_KEY"], "shared")

    def test_model_list_error_does_not_echo_secret_transport_details(self):
        def failing_opener(*args, **kwargs):
            raise ValueError("synthetic-secret-from-transport")
        with self.assertRaises(RuntimeError) as error:
            mr.list_models("local", base_url="http://model.example.com/private-token/v1", opener=failing_opener)
        self.assertNotIn("synthetic-secret", str(error.exception))
        self.assertNotIn("private-token", str(error.exception))

    def test_approval_covers_provider_address_and_key(self):
        digests = {mr.secret_digest(provider, key, address) for provider, key, address in (
            ("anthropic", "fixture", ""), ("openai", "fixture", ""),
            ("local", "fixture", "http://model.example.com/v1"),
            ("local", "other", "http://model.example.com/v1"),
            ("local", "fixture", "http://other.example.com/v1"))}
        self.assertEqual(len(digests), 5)

    def test_relay_edits_keep_defaults_then_custom_destinations(self):
        with tempfile.TemporaryDirectory() as folder:
            config = str(Path(folder) / "relay.conf")
            self.assertEqual(allow_endpoint("MODEL.example.com:11434", config), (*DEFAULT_ALLOW, "model.example.com:11434"))
            self.assertEqual(allow_endpoint("model.example.com:11434", config), (*DEFAULT_ALLOW, "model.example.com:11434"))
            Path(config).write_text("# explicit root policy\nALLOW=existing.example.com:443\n")
            self.assertEqual(allow_endpoint("new.example.com:8000", config), ("existing.example.com:443", "new.example.com:8000"))
            for endpoint in ("bad", "x:0", "x:65536", "x:443\nALLOW=bad:80", "x:443 --bad"):
                with self.assertRaises(ValueError):
                    allow_endpoint(endpoint, config)

    def test_secret_links_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            target, link = Path(folder) / "secret", Path(folder) / "link"
            target.write_text("OPENAI_API_KEY=fixture\n")
            target.chmod(0o600)
            link.symlink_to(target)
            with self.assertRaises(OSError):
                read_secrets([link])

    def test_root_precheck_can_read_the_run_accounts_private_tier(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "secrets.env"
            file.write_text("OPENAI_API_KEY=fixture\n")
            file.chmod(0o600)
            actual_uid = os.getuid()
            with patch("os.getuid", return_value=0), patch("pwd.getpwnam", return_value=SimpleNamespace(pw_uid=actual_uid)):
                self.assertEqual(read_secrets([file]), {"OPENAI_API_KEY": "fixture"})


if __name__ == "__main__":
    unittest.main()
