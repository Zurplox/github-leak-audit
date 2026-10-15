import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from scanner.config import Config
from scanner.dashboard import DashboardServer
from scanner.models import FindingRecord
from scanner.storage import ScanQueue


def finding():
    sha = "a" * 40
    return FindingRecord(
        "f" * 64, "Stripe", 90, "owner/repo", "main", sha, "config/.env", 2,
        f"https://github.com/owner/repo/blob/{sha}/config/.env#L2", "sk_l...x", "e" * 64,
        ("rule",), ("evidence",), "2026-10-14T00:00:00+00:00",
    )


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.assets = root / "assets"
        self.assets.mkdir()
        (self.assets / "index.html").write_text("<html>dashboard</html>", encoding="utf-8")
        (self.assets / "app.js").write_text("console.log('ok')", encoding="utf-8")
        self.config = Config()
        self.config = self.config.__class__(
            self.config.mode, self.config.search, self.config.broad, self.config.scan,
            self.config.detection, self.config.reports.__class__(root / "reports", root / "state.sqlite3"),
        )
        queue = ScanQueue(self.config.reports.state_database)
        queue.save_finding(finding())
        queue.close()
        self.manager = Mock()
        self.manager.status.return_value = {
            "status": "idle", "mode": None, "repository": None, "startedAt": None,
            "updatedAt": None, "lastError": None,
            "counters": {"queued": 0, "inProgress": 0, "done": 0, "failed": 0, "findings": 1, "requests": 0},
            "continuous": False, "pollIntervalSeconds": 300,
        }
        self.manager.start.side_effect = lambda mode, repository, once: {"status": "running"}
        self.manager.pause.return_value = {"status": "paused"}
        self.manager.stop.return_value = {"status": "stopped"}
        self.server = DashboardServer("127.0.0.1", 0, self.manager, self.config, static_root=self.assets)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port)

    def tearDown(self):
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        encoded = body if isinstance(body, bytes) else json.dumps(body) if body is not None else None
        self.connection.request(method, path, body=encoded, headers=headers)
        response = self.connection.getresponse()
        raw = response.read()
        return response.status, raw, json.loads(raw) if response.getheader("Content-Type", "").startswith("application/json") else None

    def test_status_findings_summary_and_static_root_are_safe(self):
        status, _, payload = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "idle")
        status, raw, payload = self.request("GET", "/api/findings?page=1&pageSize=10&provider=stripe")
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"][0]["provider"], "Stripe")
        self.assertNotIn(b'"value"', raw)
        status, _, payload = self.request("GET", "/api/summary")
        self.assertEqual(status, 200)
        self.assertEqual(payload["totalFindings"], 1)
        status, raw, _ = self.request("GET", "/")
        self.assertEqual((status, raw), (200, b"<html>dashboard</html>"))

    def test_invalid_start_and_disclosure_use_structured_json(self):
        status, _, payload = self.request("POST", "/api/scans", {"mode": "bad", "once": True})
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "VALIDATION_ERROR")
        status, _, payload = self.request("GET", "/api/disclosures/not-an-id")
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "VALIDATION_ERROR")
        status, _, payload = self.request("GET", "/api/disclosures/" + "f" * 64)
        self.assertEqual(status, 200)
        self.assertIn("Open exact GitHub source", payload["content"])

    def test_scan_controls_conflict_and_pagination_errors_are_structured(self):
        status, _, payload = self.request("POST", "/api/scans", {"mode": "repo", "repository": "owner/repo", "once": True})
        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "running")
        status, _, payload = self.request("POST", "/api/scans/pause", {})
        self.assertEqual((status, payload["status"]), (200, "paused"))
        status, _, payload = self.request("POST", "/api/scans/stop", {})
        self.assertEqual((status, payload["status"]), (200, "stopped"))
        status, _, payload = self.request("GET", "/api/findings?pageSize=101")
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "VALIDATION_ERROR")
        status, _, payload = self.request("GET", "/api/findings?unknown=x")
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "VALIDATION_ERROR")
        status, _, payload = self.request("POST", "/api/scans", b"not-json")
        self.assertEqual(status, 422)
        status, _, payload = self.request("GET", "/api/disclosures/" + "0" * 64)
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")

    def test_static_subresources_are_served_and_traversal_is_rejected(self):
        status, raw, _ = self.request("GET", "/static/app.js")
        self.assertEqual((status, raw), (200, b"console.log('ok')"))
        status, _, payload = self.request("GET", "/static/%2e%2e/%2e%2e/state.sqlite3")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")

    def test_non_loopback_bind_is_rejected(self):
        with self.assertRaises(ValueError):
            DashboardServer("0.0.0.0", 0, self.manager, self.config, static_root=self.assets)


if __name__ == "__main__":
    unittest.main()
