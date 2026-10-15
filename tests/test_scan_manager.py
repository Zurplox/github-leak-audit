import os
from pathlib import Path
import tempfile
import time
import unittest
from threading import Event
from dataclasses import replace
from unittest.mock import patch

from scanner.config import Config
from scanner.models import EventPage, FindingRecord, QueueItem, Repository, SearchPage, SearchResult
from scanner.github_client import AuthenticationError, GitHubClientError, RateLimitError
from scanner.scan_manager import ScanManager, ScanConflict, ScanConfigurationError, ScanValidationError
from scanner.storage import ScanQueue
from tests.test_repository_scan import FakeClient as RepositoryClient, synthetic_value


def safe_finding():
    sha = "a" * 40
    return FindingRecord(
        "f" * 64, "Stripe", 90, "owner/repo", "main", sha, "config/.env", 2,
        f"https://github.com/owner/repo/blob/{sha}/config/.env#L2", "sk_l...x", "e" * 64,
        ("rule",), ("evidence",), "2026-10-14T00:00:00+00:00",
    )


class FakeClient:
    def repository(self, owner, name):
        return Repository(f"{owner}/{name}", "main", owner)


class BlockingClient(FakeClient):
    def __init__(self):
        self.entered = Event()
        self.release = Event()

    def repository(self, owner, name):
        self.entered.set()
        if not self.release.wait(2):
            raise RuntimeError("test client was not released")
        return super().repository(owner, name)


class ScanManagerTests(unittest.TestCase):
    def config(self, root):
        return replace(Config(), reports=replace(Config().reports,
            output_directory=root / "reports", state_database=root / "state.sqlite3"),
            scan=replace(Config().scan, include_history=False))

    def wait_for(self, predicate):
        for _ in range(100):
            if predicate():
                return
            time.sleep(0.01)
        self.fail("manager did not reach expected state")

    def test_repo_once_run_completes_and_reports_safe_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            with patch.dict(os.environ, {"SCANNER_FINGERPRINT_KEY": "test-key"}, clear=True), \
                 patch("scanner.scan_manager.GitHubClient", return_value=FakeClient()), \
                 patch("scanner.scan_manager.scan_queue_item", return_value=[safe_finding()]):
                manager = ScanManager(config)
                try:
                    result = manager.start("repo", "owner/repo", True)
                    self.assertIn(result["status"], {"running", "completed"})
                    self.wait_for(lambda: manager.status()["status"] == "completed")
                    status = manager.status()
                    self.assertEqual(status["counters"]["findings"], 1)
                    self.assertEqual(status["counters"]["done"], 1)
                    self.assertEqual(status["mode"], "repo")
                finally:
                    manager.close()

    def test_active_start_conflicts_and_invalid_repo_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            client = BlockingClient()
            manager = ScanManager(config, client_factory=lambda secrets: client)
            try:
                with self.assertRaises(ScanValidationError):
                    manager.start("repo", "not-a-repository", True)
                with patch.dict(os.environ, {"SCANNER_FINGERPRINT_KEY": "test-key"}, clear=True):
                    with patch("scanner.scan_manager.GitHubClient", return_value=FakeClient()), \
                         patch("scanner.scan_manager.scan_queue_item", side_effect=lambda *args: []):
                        manager.start("repo", "owner/repo", False)
                        self.assertTrue(client.entered.wait(2))
                        with self.assertRaises(ScanConflict):
                            manager.start("repo", "owner/repo", True)
                        manager.stop()
                        client.release.set()
            finally:
                client.release.set()
                manager.close()

    def test_api_read_does_not_requeue_active_worker_item(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            entered, release = Event(), Event()
            def scan(*args):
                entered.set()
                self.assertTrue(release.wait(2))
                return []
            manager = ScanManager(config, fingerprint_key=b"local-key", client_factory=lambda secrets: FakeClient())
            try:
                with patch("scanner.scan_manager.scan_queue_item", side_effect=scan):
                    manager.start("repo", "owner/repo", True)
                    self.assertTrue(entered.wait(2))
                    for _ in range(3):
                        self.assertEqual(manager.status()["counters"]["inProgress"], 1)
                        reader = ScanQueue(config.reports.state_database, read_only=True)
                        try:
                            self.assertEqual(reader.queue_counts()["in_progress"], 1)
                            with self.assertRaises(Exception):
                                reader.enqueue(QueueItem("owner/other", "main", ""))
                        finally:
                            reader.close()
                    release.set()
                    self.wait_for(lambda: manager.status()["status"] == "completed")
            finally:
                release.set()
                manager.close()

    def test_pause_and_stop_finish_item_then_release_entire_unstarted_batch(self):
        for action, expected in (("pause", "paused"), ("stop", "stopped")):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                config = self.config(Path(directory))
                entered, release = Event(), Event()
                scanned = []
                class SearchClient(FakeClient):
                    def search_code(self, query, page=1):
                        return SearchPage(tuple(SearchResult("owner/repo", f"{i}.env", "main", "", "") for i in range(3)), 3, False)
                def scan(client, item, *args):
                    scanned.append(item.path)
                    entered.set()
                    self.assertTrue(release.wait(2))
                    return [safe_finding()]
                manager = ScanManager(config, fingerprint_key=b"local-key", client_factory=lambda secrets: SearchClient())
                try:
                    with patch("scanner.scan_manager.scan_queue_item", side_effect=scan):
                        manager.start("search", None, True)
                        self.assertTrue(entered.wait(2))
                        getattr(manager, action)()
                        with self.assertRaises(ScanConflict):
                            manager.start("search", None, True)
                        release.set()
                        self.wait_for(lambda: manager.status()["status"] == expected)
                        status = manager.status()
                        self.assertEqual(scanned, ["0.env"])
                        self.assertEqual(status["counters"]["done"], 1)
                        self.assertEqual(status["counters"]["queued"], 2)
                        self.assertEqual(status["counters"]["inProgress"], 0)
                        self.assertEqual(status["counters"]["findings"], 1)
                finally:
                    release.set()
                    manager.close()

    def test_errors_do_not_serialize_raw_exception_text_and_pending_work_is_released(self):
        for error, expected, queue_state in (
            (RateLimitError(30), "rate_limited", "pending"),
            (AuthenticationError(synthetic_value()), "failed", "failed"),
            (GitHubClientError(synthetic_value()), "failed", "failed"),
            (RuntimeError(synthetic_value()), "failed", "failed"),
        ):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                config = self.config(Path(directory))
                manager = ScanManager(config, fingerprint_key=b"local-key", client_factory=lambda secrets: FakeClient())
                try:
                    with patch("scanner.scan_manager.scan_queue_item", side_effect=error):
                        manager.start("repo", "owner/repo", True)
                        self.wait_for(lambda: manager.status()["status"] == expected)
                        status = manager.status()
                        self.assertNotIn(synthetic_value(), str(status))
                        self.assertEqual(status["counters"]["queued" if queue_state == "pending" else "failed"], 1)
                        self.assertEqual(status["counters"]["inProgress"], 0)
                finally:
                    manager.close()

    def test_continuous_broad_repeats_discovery_and_stop_interrupts_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            config = replace(config, broad=replace(config.broad, poll_interval_seconds=0.02, backfill_days=0))
            repeated = Event()
            class EventClient(FakeClient):
                passes = 0
                def list_public_events(self, cursor=None):
                    self.passes += 1
                    if self.passes == 2:
                        repeated.set()
                    return EventPage(("owner/repo",), None)
            client = EventClient()
            manager = ScanManager(config, fingerprint_key=b"local-key", client_factory=lambda secrets: client)
            try:
                with patch("scanner.scan_manager.scan_queue_item", return_value=[]):
                    manager.start("broad", None, False)
                    self.assertTrue(repeated.wait(2))
                    manager.stop()
                    self.wait_for(lambda: manager.status()["status"] == "stopped")
            finally:
                manager.close()

    def test_continuous_once_and_idle_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            config = replace(config, broad=replace(config.broad, backfill_days=0))
            class EventClient(FakeClient):
                passes = 0
                def list_public_events(self, cursor=None):
                    self.passes += 1
                    return EventPage((), None)
            client = EventClient()
            manager = ScanManager(config, fingerprint_key=b"local-key", client_factory=lambda secrets: client)
            try:
                self.assertEqual(manager.pause()["status"], "idle")
                self.assertEqual(manager.stop()["status"], "idle")
                manager.start("broad", None, True)
                self.wait_for(lambda: manager.status()["status"] == "completed")
                self.assertEqual(client.passes, 1)
                self.assertFalse(manager.status()["continuous"])
            finally:
                manager.close()

    def test_missing_configuration_and_restart_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            queue = ScanQueue(config.reports.state_database)
            queue.enqueue(QueueItem("owner/repo", "main", ""))
            queue.claim(1)
            queue.close()
            manager = ScanManager(config)
            try:
                self.assertEqual(manager.status()["counters"]["queued"], 1)
                with patch.dict(os.environ, {}, clear=True):
                    with self.assertRaises(ScanConfigurationError):
                        manager.start("search", None, True)
                self.assertEqual(manager.status()["status"], "idle")
            finally:
                manager.close()

    def test_real_engine_finding_artifacts_are_masked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = ScanManager(self.config(root), fingerprint_key=b"local-key",
                                  client_factory=lambda secrets: RepositoryClient())
            try:
                manager.start("repo", "sample/repo", True)
                self.wait_for(lambda: manager.status()["status"] == "completed")
                self.assertEqual(manager.status()["counters"]["findings"], 1)
                for artifact in root.rglob("*"):
                    if artifact.is_file():
                        self.assertNotIn(synthetic_value().encode(), artifact.read_bytes())
            finally:
                manager.close()


if __name__ == "__main__":
    unittest.main()
