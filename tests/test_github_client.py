import json
import unittest

from scanner.github_client import (GitHubClient, GitHubClientError, RateLimitError,
                                   TruncatedTreeError)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class GitHubClientTests(unittest.TestCase):
    def test_search_parses_safe_fields_and_auth_header(self):
        transport = FakeTransport([
            (200, {}, json.dumps({
                "total_count": 1,
                "incomplete_results": False,
                "items": [{
                    "path": ".env",
                    "sha": "a" * 40,
                    "html_url": "https://github.com/acme/app/blob/" + "a" * 40 + "/.env",
                    "repository": {"full_name": "acme/app", "default_branch": "main", "private": False, "visibility": "public"},
                }],
            }).encode()),
        ])
        client = GitHubClient("token", transport=transport)
        page = client.search_code("filename:.env password")
        self.assertEqual(page.items[0].repository, "acme/app")
        request, timeout = transport.requests[0]
        self.assertEqual(request.headers["Authorization"], "Bearer token")
        self.assertIn("q=filename%3A.env+password", request.full_url)
        self.assertGreater(timeout, 0)

    def test_rate_limit_retries_then_succeeds(self):
        transport = FakeTransport([
            (429, {"Retry-After": "0"}, b"{}"),
            (200, {}, b'{"ok": true}'),
        ])
        client = GitHubClient(None, transport=transport, sleeper=lambda _: None)
        self.assertEqual(client.request("GET", "/rate"), {"ok": True})
        self.assertEqual(len(transport.requests), 2)

    def test_exhausted_rate_limit_raises_without_unbounded_retry(self):
        transport = FakeTransport([
            (403, {"X-RateLimit-Remaining": "0"}, b"{}"),
            (403, {"X-RateLimit-Remaining": "0"}, b"{}"),
            (403, {"X-RateLimit-Remaining": "0"}, b"{}"),
            (403, {"X-RateLimit-Remaining": "0"}, b"{}"),
        ])
        client = GitHubClient(None, transport=transport, sleeper=lambda _: None, max_retries=2)
        with self.assertRaises(RateLimitError):
            client.request("GET", "/rate")
        self.assertEqual(len(transport.requests), 3)

    def test_invalid_path_and_malformed_payload_are_rejected(self):
        transport = FakeTransport([(200, {}, b"[]")])
        client = GitHubClient(None, transport=transport)
        with self.assertRaises(GitHubClientError):
            client.request("GET", "https://example.invalid")

        transport = FakeTransport([(200, {}, b"[]")])
        client = GitHubClient(None, transport=transport)
        with self.assertRaises(GitHubClientError):
            client.search_code("secret")

    def test_search_blob_sha_is_not_a_commit_sha(self):
        blob = "b" * 40
        transport = FakeTransport([(200, {}, json.dumps({
            "total_count": 1, "incomplete_results": False,
            "items": [{"path": "app.py", "sha": blob,
                       "html_url": f"https://github.com/acme/app/blob/{blob}/app.py",
                       "repository": {"full_name": "acme/app", "default_branch": "main",
                                      "private": False}}]}).encode())])
        page = GitHubClient(None, transport=transport).search_code("token")
        self.assertEqual(page.items[0].ref, "main")
        self.assertEqual(page.items[0].commit_sha, "")

    def test_search_requires_explicit_public_repository_metadata(self):
        blob = "b" * 40
        transport = FakeTransport([(200, {}, json.dumps({
            "total_count": 1, "incomplete_results": False,
            "items": [{"path": ".env", "sha": blob,
                       "html_url": f"https://github.com/acme/app/blob/{blob}/.env",
                       "repository": {"full_name": "acme/app", "default_branch": "main"}}]}).encode())])
        with self.assertRaises(GitHubClientError):
            GitHubClient(None, transport=transport).search_code("token")

    def test_content_decodes_bounded_base64_and_resolves_commit(self):
        sha = "c" * 40
        transport = FakeTransport([
            (200, {}, json.dumps({"type": "file", "encoding": "base64", "path": ".env",
                                  "size": 6, "content": "c2VjcmV0\n"}).encode()),
            (200, {}, json.dumps({"sha": sha}).encode()),
        ])
        client = GitHubClient(None, transport=transport)
        self.assertEqual(client.content("acme", "app", ".env", "main"), "secret")
        self.assertEqual(client.resolve_commit("acme", "app", "main"), sha)

    def test_truncated_tree_is_explicit_error(self):
        transport = FakeTransport([(200, {}, json.dumps({"truncated": True, "tree": []}).encode())])
        with self.assertRaises(TruncatedTreeError):
            GitHubClient(None, transport=transport).tree("acme", "app", "main")

    def test_redirect_is_not_followed_and_retry_after_is_exposed(self):
        transport = FakeTransport([(302, {"Location": "https://evil.example/steal"}, b"")])
        with self.assertRaises(GitHubClientError):
            GitHubClient("secret-token", transport=transport).request("GET", "/events")
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.requests[0][0].full_url, "https://api.github.com/events")

        limited = FakeTransport([(429, {"Retry-After": "7"}, b"{}")])
        with self.assertRaises(RateLimitError) as caught:
            GitHubClient(None, transport=limited, max_retries=0).request("GET", "/events")
        self.assertEqual(caught.exception.retry_after, 7.0)

    def test_http_404_keeps_status_for_stale_content_handling(self):
        client = GitHubClient(None, transport=FakeTransport([(404, {}, b"{}")]))
        with self.assertRaises(GitHubClientError) as caught:
            client.content("acme", "app", ".env", "main")
        self.assertEqual(caught.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
