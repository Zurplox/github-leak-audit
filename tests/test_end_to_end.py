import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace

from scanner.config import Config
from scanner.models import QueueItem
from scanner.repository_scan import scan_queue_item
from scanner.reports import write_disclosure_draft, write_jsonl
from scanner.storage import ScanQueue
from tests.test_repository_scan import FakeClient, HEAD, KEY, synthetic_value


class EndToEndTests(unittest.TestCase):
    def test_offline_scan_resume_and_all_artifacts_are_redacted(self):
        runtime = Path(__file__).resolve().parents[1] / ".superpowers" / "report-scan-tests"
        runtime.mkdir(parents=True, exist_ok=True)
        value = synthetic_value()
        source = "# local synthetic data\nAPI_KEY=" + value + "\nTOKEN=YOUR_API_KEY\nTOKEN=************\n"
        config = Config()
        config = replace(config, scan=replace(config.scan, include_history=False))
        output = io.StringIO()
        with tempfile.TemporaryDirectory(dir=runtime) as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                queue = ScanQueue(database)
                try:
                    item = QueueItem("sample/repo", "main", "")
                    self.assertTrue(queue.enqueue(item))
                    records = scan_queue_item(FakeClient(source), queue.claim(1)[0], config, KEY)
                    self.assertEqual(len(records), 1)
                    self.assertEqual(records[0].provider, "Stripe")
                    self.assertEqual(records[0].commit_sha, HEAD)
                    for finding in records:
                        self.assertTrue(queue.save_finding(finding))
                        self.assertFalse(queue.save_finding(finding))
                    queue.complete(item.identity, "done")
                    write_jsonl(queue.list_findings(), root / "findings.jsonl")
                    draft = write_disclosure_draft(records[0], root / "drafts")
                    rows = [tuple(row) for row in queue.connection.execute("SELECT * FROM findings")]
                    self.assertFalse(value in json.dumps(rows), "complete candidate found in SQLite rows")
                    self.assertIn("Open exact GitHub source", draft.read_text(encoding="utf-8"))
                finally:
                    queue.close()
                resumed = ScanQueue(database)
                try:
                    self.assertEqual(resumed.claim(1), [])
                    self.assertEqual(len(resumed.list_findings()), 1)
                finally:
                    resumed.close()
            for artifact in root.rglob("*"):
                if artifact.is_file():
                    self.assertFalse(value.encode() in artifact.read_bytes(), "complete candidate found in output artifact")
            self.assertFalse(value in output.getvalue(), "complete candidate found in captured output")
