import unittest
from datetime import datetime, timezone

from scanner.config import BroadConfig, SearchConfig
from scanner.discovery import BroadDiscovery, SearchDiscovery
from scanner.github_client import RepositorySearchPage
from scanner.models import EventPage, Repository, SearchPage, SearchResult


class FakeClient:
    def search_code(self, query, page=1):
        return SearchPage((SearchResult("acme/app", ".env", "main", "abc", "https://github.com/acme/app/blob/abc/.env"),), 1, False)

    def list_public_events(self, cursor=None):
        return EventPage(("acme/app", "acme/other"), None)

    def repository(self, owner, name):
        return Repository(f"{owner}/{name}", "main", owner)

    def search_repositories(self, query, page=1):
        return RepositorySearchPage((), 0, False)

    def commits(self, owner, name, since=None, limit=10):
        return []


class BackfillClient(FakeClient):
    def __init__(self):
        self.searches = []

    def list_public_events(self, cursor=None):
        return EventPage((), None)

    def search_repositories(self, query, page=1):
        self.searches.append((query, page))
        if page == 1:
            return RepositorySearchPage((Repository("acme/new", "main", "acme"),), 2, True)
        return RepositorySearchPage((Repository("acme/second", "trunk", "acme"),), 2, False)

    def commits(self, owner, name, since=None, limit=10):
        return []


class DiscoveryTests(unittest.TestCase):
    def test_search_discovery_normalizes_results(self):
        items = list(SearchDiscovery(FakeClient(), SearchConfig(queries=("secret",))).discover())
        self.assertEqual(items[0].repository, "acme/app")
        self.assertEqual(items[0].path, ".env")

    def test_broad_discovery_deduplicates_public_repositories(self):
        items = list(BroadDiscovery(FakeClient(), BroadConfig(max_repositories=10)).discover())
        self.assertEqual([item.repository for item in items], ["acme/app", "acme/other"])

    def test_broad_backfill_is_bounded_and_uses_created_date_query(self):
        client = BackfillClient()
        items = list(BroadDiscovery(client, BroadConfig(
            recent_activity_pages=1, backfill_days=3, max_repositories=2),
            now=datetime(2026, 10, 13, tzinfo=timezone.utc)).discover())
        self.assertEqual([item.repository for item in items], ["acme/new", "acme/second"])
        self.assertEqual(len(client.searches), 2)
        self.assertIn("is:public created:2026-10-10..2026-10-13", client.searches[0][0])

    def test_search_languages_and_results_have_global_cap_and_blank_blob_sha(self):
        class SearchClient(FakeClient):
            def __init__(self):
                self.calls = []

            def search_code(self, query, page=1):
                self.calls.append((query, page))
                return SearchPage((SearchResult("acme/app", "x.py", "main", "d" * 40,
                    "https://github.com/acme/app/blob/" + "d" * 40 + "/x.py"),), 1, False)

        client = SearchClient()
        items = list(SearchDiscovery(client, SearchConfig(queries=("secret",),
            max_results_per_query=1, languages=("Python", "Go"))).discover())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].commit_sha, "")
        self.assertIn('language:"Python"', client.calls[0][0])


if __name__ == "__main__":
    unittest.main()
