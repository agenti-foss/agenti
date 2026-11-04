"""The clean-install setup driver checks the skip path without logging secrets."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TEST_SETUP = Path(__file__).resolve().parent.parent / "packaging" / "test-setup.py"
SENTINEL = "SYNTHETIC-ENROLMENT-SECRET-MUST-NOT-APPEAR"


class SetupHarnessTest(unittest.TestCase):
    def run_fake_setup(self, skip_message: bool):
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder) / "agenti"
            fake.write_text(f'''#!/usr/bin/env python3
print("was created by an earlier setup but has no password yet", flush=True)
input("choose a password")
print("it needs at least 8", flush=True)
input("choose a password")
input("type it again")
print("secret: {SENTINEL}", flush=True)
input("turn the vault on?")
input("set it now?")
{f'print("skipped — configure the provider you want", flush=True)' if skip_message else 'pass'}
input("choose 1, 2 or 3")
print("Done.", flush=True)
''')
            fake.chmod(0o755)
            result = subprocess.run([sys.executable, str(TEST_SETUP)],
                                    env={**os.environ, "PATH": folder + os.pathsep + os.environ["PATH"], "SHOW": "1"},
                                    capture_output=True, text=True, timeout=25)
            self.assertNotIn(SENTINEL, result.stdout + result.stderr)
            return result

    def test_key_skip_is_accepted(self):
        result = self.run_fake_setup(True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[ OK ] setup the API key was skipped", result.stdout)

    def test_failure_does_not_print_enrollment_output(self):
        result = self.run_fake_setup(False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("setup output withheld", result.stdout)


if __name__ == "__main__":
    unittest.main()
