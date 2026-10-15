import tempfile
import unittest
from pathlib import Path
from scanner.models import FindingRecord

from scanner.models import QueueItem
from scanner.storage import ScanQueue


class StorageTests(unittest.TestCase):
    def test_queue_counts_and_finding_page_are_safe_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = ScanQueue(Path(directory) / "state.sqlite3")
            try:
                items = [QueueItem("owner/repo", "main", str(index), f"f{index}.env") for index in range(3)]
                for item in items:
                    queue.enqueue(item)
                queue.complete(items[0].identity, "done")
                queue.complete(items[1].identity, "failed")
                finding = FindingRecord(
                    "a" * 64, "Stripe", 90, "owner/repo", "main", "b" * 40,
                    "config/.env", 2, "https://github.com/owner/repo/blob/" + "b" * 40 + "/config/.env#L2",
                    "sk_l...x", "c" * 64, ("stripe",), ("format",), "2026-10-14T00:00:00+00:00",
                )
                queue.save_finding(finding)
                self.assertEqual(queue.queue_counts(), {
                    "pending": 1, "in_progress": 0, "done": 1, "failed": 1,
                })
                rows, total = queue.list_findings_page(1, 10, provider="stripe")
                self.assertEqual(total, 1)
                self.assertEqual(rows[0].finding_id, finding.finding_id)
            finally:
                queue.close()

    def test_finding_page_rejects_invalid_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = ScanQueue(Path(directory) / "state.sqlite3")
            try:
                for page, page_size in ((0, 10), (1, 0), (1, 101)):
                    with self.assertRaises(ValueError):
                        queue.list_findings_page(page, page_size)
            finally:
                queue.close()

    def test_queue_deduplicates_and_resumes_claimed_work(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = ScanQueue(Path(directory) / "state.sqlite3")
            item = QueueItem("owner/repo", "main", "abc123", "config/.env")

            self.assertTrue(queue.enqueue(item))
            self.assertFalse(queue.enqueue(item))
            claimed = queue.claim(1)
            self.assertEqual(len(claimed), 1)
            self.assertEqual(claimed[0].identity, item.identity)

            queue.complete(item.identity, "done")
            self.assertEqual(queue.claim(1), [])
            queue.close()

    def test_checkpoint_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = ScanQueue(Path(directory) / "state.sqlite3")
            self.assertIsNone(queue.get_checkpoint("events"))
            queue.checkpoint("events", "cursor-2")
            self.assertEqual(queue.get_checkpoint("events"), "cursor-2")
            queue.close()

    def test_interrupted_in_progress_work_is_requeued_on_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            first = ScanQueue(path)
            item = QueueItem("owner/repo", "main", "abc123", "config/.env")
            first.enqueue(item)
            self.assertEqual(len(first.claim(1)), 1)
            first.close()

            restarted = ScanQueue(path)
            try:
                self.assertEqual([queued.identity for queued in restarted.claim(1)], [item.identity])
            finally:
                restarted.close()


if __name__ == "__main__":
    unittest.main()
