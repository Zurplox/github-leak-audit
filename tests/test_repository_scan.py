import unittest
from dataclasses import replace

from scanner.config import Config
from scanner.models import CommitSummary, QueueItem, Repository, TreeEntry
from scanner.repository_scan import MAX_FILES_PER_SCAN, scan_queue_item, select_candidate_files


HEAD = "a" * 40
OLD = "b" * 40
KEY = b"offline-fingerprint-material"


def synthetic_value():
    return "sk_" + "live_" + "7nQ2rV9mK4sP6dH8" + "uB3wZ5"


class FakeClient:
    def __init__(self, source=None):
        self.source = source if source is not None else "# settings\nAPI_KEY=" + synthetic_value() + "\n"
        self.calls = []
        self.files = [TreeEntry("config/a #?.env", "blob", 120, "c" * 40)]
        self.error = None
        self.history = []

    def repository(self, owner, name):
        self.calls.append(("repository", owner, name))
        return Repository("sample/repo", "main", "sample")

    def resolve_commit(self, owner, name, ref):
        self.calls.append(("resolve", ref))
        return OLD if ref == OLD else HEAD

    def tree(self, owner, name, ref):
        self.calls.append(("tree", ref))
        return self.files

    def content(self, owner, name, path, ref):
        self.calls.append(("content", path, ref))
        if self.error:
            raise self.error
        return self.source

    def commits(self, owner, name, since=None):
        self.calls.append(("commits", since))
        return self.history


class RepositoryScanTests(unittest.TestCase):
    def config(self, **scan):
        config = Config()
        return replace(config, scan=replace(config.scan, include_history=False, **scan))

    def test_selection_excludes_large_binary_generated_vendor_and_duplicates(self):
        paths = [".env", ".env.production", "src/main.py", "settings", "vendor/x.env",
                 "node_modules/x.py", "dist/a.js", ".git/config", "x.png", "bundle.min.js"]
        entries = [TreeEntry(path, "blob", 100, "c" * 40) for path in paths]
        entries += [TreeEntry("large.env", "blob", 9999, "c" * 40),
                    TreeEntry("directory.env", "tree", 0, "c" * 40), entries[0]]
        selected = select_candidate_files(entries, self.config(max_file_size=200))
        self.assertEqual({entry.path for entry in selected}, {".env", ".env.production", "src/main.py", "settings"})
        self.assertEqual(len(selected), 4)

    def test_selection_honors_tree_extension_and_file_caps(self):
        entries = [TreeEntry(f"f{i}.env", "blob", 10, "c" * 40) for i in range(MAX_FILES_PER_SCAN + 10)]
        self.assertEqual(len(select_candidate_files(entries, self.config())), MAX_FILES_PER_SCAN)
        self.assertEqual(len(select_candidate_files(entries, self.config(max_tree_entries=2))), 2)
        self.assertEqual(select_candidate_files(entries, self.config(allowed_extensions=(".py",))), [])

    def test_provider_generic_merge_exact_line_and_url_no_raw_value(self):
        client = FakeClient()
        records = scan_queue_item(client, QueueItem("sample/repo", "main", ""), self.config(), KEY)
        self.assertEqual(len(records), 1)
        finding = records[0]
        self.assertEqual(finding.provider, "Stripe")
        self.assertIn("generic-assignment", finding.rule_ids)
        self.assertEqual(finding.line_number, 2)
        self.assertEqual(finding.commit_sha, HEAD)
        self.assertEqual(finding.permalink, f"https://github.com/sample/repo/blob/{HEAD}/config/a%20%23%3F.env#L2")
        self.assertEqual(len(finding.finding_id), 64)
        self.assertFalse(synthetic_value() in repr(finding), "raw candidate escaped safe record")
        self.assertIn(("content", finding.path, HEAD), client.calls)

    def test_direct_search_match_ignores_blob_sha_and_resolves_branch(self):
        client = FakeClient()
        records = scan_queue_item(client, QueueItem("sample/repo", "main", "d" * 40, ".env"), self.config(), KEY)
        self.assertEqual(records[0].commit_sha, HEAD)
        self.assertIn(("resolve", "main"), client.calls)
        self.assertIn(("content", ".env", HEAD), client.calls)

    def test_missing_file_skipped_but_auth_and_rate_limit_propagate(self):
        client = FakeClient()
        client.error = FileNotFoundError("missing")
        self.assertEqual(scan_queue_item(client, QueueItem("sample/repo", "main", ""), self.config(), KEY), [])
        for error in (PermissionError("authorization failed"), RuntimeError("rate limited")):
            client.error = error
            with self.assertRaises(type(error)):
                scan_queue_item(client, QueueItem("sample/repo", "main", ""), self.config(), KEY)

    def test_oversize_or_binary_content_not_scanned(self):
        for source in ("\0API_KEY=" + synthetic_value(), "API_KEY=" + synthetic_value()):
            client = FakeClient(source)
            config = self.config(max_file_size=30) if "\0" not in source else self.config()
            client.files = [TreeEntry("x.env", "blob", 10, "c" * 40)]
            self.assertEqual(scan_queue_item(client, QueueItem("sample/repo", "main", ""), config, KEY), [])

    def test_finding_identity_stable_and_distinct_for_location_commit_and_key(self):
        client = FakeClient()
        item = QueueItem("sample/repo", "main", HEAD)
        first = scan_queue_item(client, item, self.config(), KEY)[0]
        same = scan_queue_item(client, item, self.config(), KEY)[0]
        self.assertEqual(first.finding_id, same.finding_id)
        for changed, key in ((replace(item, commit_sha=OLD), KEY), (replace(item, path="x.env"), KEY), (item, b"different-key")):
            other = scan_queue_item(client, changed, self.config(), key)[0]
            self.assertNotEqual(first.finding_id, other.finding_id)

    def test_history_uses_immutable_snapshot_for_secret_deleted_at_head(self):
        class HistoryClient(FakeClient):
            def content(self, owner, name, path, ref):
                self.calls.append(("content", path, ref))
                return self.source if ref == OLD else "# removed\n"

        client = HistoryClient()
        client.history = [CommitSummary(HEAD, "current", None), CommitSummary(OLD, "old", None)]
        records = scan_queue_item(client, QueueItem("sample/repo", "main", ""), Config(), KEY)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].commit_sha, OLD)
        self.assertEqual(records[0].line_number, 2)
        self.assertIn(f"/blob/{OLD}/", records[0].permalink)

    def test_history_and_total_file_requests_bounded(self):
        client = FakeClient("# no values")
        client.files = [TreeEntry(f"f{i}.env", "blob", 10, "c" * 40) for i in range(MAX_FILES_PER_SCAN + 1)]
        client.history = [CommitSummary(OLD, "old", None)] * 20
        scan_queue_item(client, QueueItem("sample/repo", "main", ""), Config(), KEY)
        self.assertLessEqual(sum(call[0] == "content" for call in client.calls), MAX_FILES_PER_SCAN)

    def test_invalid_repository_and_nonimmutable_commit_rejected(self):
        with self.assertRaises(ValueError):
            scan_queue_item(FakeClient(), QueueItem("../repo", "main", ""), self.config(), KEY)
        client = FakeClient()
        client.resolve_commit = lambda *args: "main"
        with self.assertRaises(ValueError):
            scan_queue_item(client, QueueItem("sample/repo", "main", ""), self.config(), KEY)
