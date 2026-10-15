import json
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace

from scanner.models import FindingRecord
from scanner.reports import render_disclosure, write_disclosure_draft, write_jsonl


RUNTIME = Path(__file__).resolve().parents[1] / ".superpowers" / "report-scan-tests"


def safe_finding():
    sha = "a" * 40
    return FindingRecord("e" * 64, "Stripe", 92, "sample/repo", "main", sha,
                         "config/.env", 2, f"https://github.com/sample/repo/blob/{sha}/config/.env#L2",
                         "sk_l...xY7z", "f" * 64, ("stripe-live",), ("format match",), "2026-10-13T00:00:00+00:00")


class ReportsTests(unittest.TestCase):
    def setUp(self):
        RUNTIME.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=RUNTIME)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_jsonl_appends_safe_records_and_encodes_newlines_controls_unicode(self):
        finding = replace(safe_finding(), path="a\nline\x00é.env", evidence=("category\nnext",))
        target = self.root / "nested" / "findings.jsonl"
        self.assertEqual(write_jsonl(iter([finding]), target), 1)
        self.assertEqual(write_jsonl([safe_finding()], target), 1)
        lines = target.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["path"], finding.path)
        self.assertNotIn("value", json.loads(lines[0]))

    def test_disclosure_private_guidance_link_and_no_claim_of_validation(self):
        finding = safe_finding()
        text = render_disclosure(finding)
        self.assertIn(f"[Open exact GitHub source]({finding.permalink})", text)
        self.assertIn("validity not tested", text.lower())
        self.assertIn("private", text.lower())
        self.assertIn("revoke", text.lower())
        self.assertIn("rotate", text.lower())
        self.assertIn(finding.masked_preview, text)

    def test_markdown_metadata_is_escaped_and_control_characters_removed(self):
        finding = replace(safe_finding(), path="[click](javascript:bad)\n<script>\x00.env", provider="**provider**",
                          masked_preview="abc`...`xyz", ref="<img src=x>")
        text = render_disclosure(finding)
        self.assertNotIn("<script>", text)
        self.assertNotIn("<img", text)
        self.assertNotIn("[click](javascript:bad)", text)
        self.assertNotIn("\x00", text)
        self.assertIn("\\[click\\]", text)
        self.assertIn("\\*\\*provider\\*\\*", text)

    def test_unsafe_permalink_rejected(self):
        for url in ("javascript:alert(1)", "https://elsewhere.invalid/path", "https://github.com@elsewhere.invalid/path", "https://github.com:444/path"):
            with self.assertRaises(ValueError):
                render_disclosure(replace(safe_finding(), permalink=url))

    def test_custom_template_receives_only_escaped_safe_fields(self):
        self.assertEqual(render_disclosure(safe_finding(), "{provider}: {line_number}"), "Stripe: 2")

    def test_filename_strict_hex_prevents_traversal(self):
        for identity in ("../escape", "a/b", "x" * 64, "f" * 65, "", "ab"):
            with self.assertRaises(ValueError):
                write_disclosure_draft(replace(safe_finding(), finding_id=identity), self.root)
        target = write_disclosure_draft(safe_finding(), self.root)
        self.assertEqual(target.name, "e" * 64 + ".md")
        self.assertEqual(target.read_text(encoding="utf-8"), render_disclosure(safe_finding()))
