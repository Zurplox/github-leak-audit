import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scanner.cli import _parser, main
from scanner.models import CommitSummary, Repository, TreeEntry


class FakeClient:
    def repository(self, owner, name):
        return Repository(f"{owner}/{name}", "main", owner)

    def resolve_commit(self, owner, name, ref):
        return "a" * 40

    def tree(self, owner, name, ref):
        return [TreeEntry("config/.env", "blob", 100, "b" * 40)]

    def content(self, owner, name, path, ref):
        return "STRIPE_KEY=sk_live_1234567890abcdefghijkl\n"

    def commits(self, owner, name, since=None):
        return []


class CliTests(unittest.TestCase):
    def test_broad_scan_accepts_once_override(self):
        args = _parser().parse_args(["scan", "broad", "--once"])
        self.assertTrue(args.once)

    def test_scan_repo_writes_safe_finding_and_draft(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.toml"
            config.write_text(
                f'mode = "search"\n[scan]\ninclude_history = false\n[reports]\n'
                f'output_directory = "{(root / "reports").as_posix()}"\n'
                f'state_database = "{(root / "state.sqlite3").as_posix()}"\n',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"SCANNER_FINGERPRINT_KEY": "cli-key"}, clear=True), \
                 patch("scanner.cli.GitHubClient", return_value=FakeClient()):
                self.assertEqual(main(["--config", str(config), "scan", "repo", "sample/repo"]), 0)

            findings = (root / "reports" / "findings.jsonl").read_text(encoding="utf-8")
            self.assertIn("Stripe", findings)
            self.assertNotIn("1234567890abcdefghijkl", findings)
            drafts = list((root / "reports" / "drafts").glob("*.md"))
            self.assertEqual(len(drafts), 1)
            self.assertIn("Open exact GitHub source", drafts[0].read_text(encoding="utf-8"))

    def test_report_list_and_draft_are_read_only_safe_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.toml"
            config.write_text(
                f'[reports]\noutput_directory = "{(root / "reports").as_posix()}"\n'
                f'state_database = "{(root / "state.sqlite3").as_posix()}"\n',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"SCANNER_FINGERPRINT_KEY": "cli-key"}, clear=True), \
                 patch("scanner.cli.GitHubClient", return_value=FakeClient()):
                self.assertEqual(main(["--config", str(config), "scan", "repo", "sample/repo"]), 0)

            state = root / "state.sqlite3"
            with patch("builtins.print") as printed:
                self.assertEqual(main(["--config", str(config), "report", "list"]), 0)
                self.assertTrue(printed.called)
                payload = json.loads(printed.call_args.args[0])
                finding_id = payload["finding_id"]
            self.assertEqual(main(["--config", str(config), "report", "draft", finding_id]), 0)


if __name__ == "__main__":
    unittest.main()
