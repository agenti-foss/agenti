"""Secret tiers resolve each key independently and preserve permission checks."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime import load_secrets


class SecretTiers(unittest.TestCase):
    def test_independent_keys_and_environment_override(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / str(i) for i in range(4)]
            for path, content in zip(paths, (
                "ANTHROPIC_API_KEY=user\n",
                "OPENAI_API_KEY=agent\n",
                "ANTHROPIC_API_KEY=org\nOPENAI_API_KEY=org\nLOCAL_LLM_BASE_URL=http://localhost:11434/v1\n",
                "LOCAL_LLM_API_KEY=shared\n",
            )):
                path.write_text(content)
                path.chmod(0o600)
            with patch.dict(os.environ, {"LOCAL_LLM_API_KEY": "exported"}, clear=True):
                load_secrets([None, Path(folder) / "missing", *paths])
                self.assertEqual(dict(os.environ), {
                    "ANTHROPIC_API_KEY": "user", "OPENAI_API_KEY": "agent",
                    "LOCAL_LLM_BASE_URL": "http://localhost:11434/v1",
                    "LOCAL_LLM_API_KEY": "exported",
                })

    def test_insecure_lower_tier_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "user", Path(folder) / "org"
            first.write_text("ANTHROPIC_API_KEY=user\n")
            first.chmod(0o600)
            second.write_text("OPENAI_API_KEY=org\n")
            second.chmod(0o644)
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(SystemExit, "REFUSING"):
                load_secrets([first, second])


if __name__ == "__main__":
    unittest.main()
