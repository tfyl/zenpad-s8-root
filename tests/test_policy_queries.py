"""Host-only regressions for misleading reference-policy query results."""

from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
QUERY = ROOT / "tools/selinux/query_policy.py"


class PolicyQueryTest(unittest.TestCase):
    def query(self, *args):
        return subprocess.run([sys.executable, str(QUERY), *args],
                              text=True, capture_output=True, timeout=15)

    def test_allow_filter_retains_known_dumpstate_property_rules(self):
        args = ("rules", "--src", "dumpstate", "--class", "property_service")
        unfiltered = self.query(*args)
        filtered = self.query(*args, "--spec", "^allow$")
        self.assertEqual(filtered.returncode, 0, filtered.stderr)
        self.assertEqual(filtered.stdout, unfiltered.stdout)
        self.assertIn("dumpstate", filtered.stdout)
        self.assertIn("ctl_default_prop", filtered.stdout)

    def test_unknown_target_and_missing_options_fail_without_broad_results(self):
        unknown = self.query("who", "--tgt", "definitely_unknown_type", "--class", "file", "--perm", "write")
        missing = self.query("who", "--class", "file", "--perm", "write")
        for result in (unknown, missing):
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")

    def test_empty_regex_selection_is_not_a_wildcard(self):
        result = self.query("who", "--tgt", "/^no_such_type$/", "--class", "file", "--perm", "write")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_invalid_regex_fails_cleanly_and_help_is_available(self):
        invalid = self.query("rules", "--src", "/[/")
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn("Traceback", invalid.stderr)
        self.assertEqual(self.query("--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
