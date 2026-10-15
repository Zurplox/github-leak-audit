"""Bounded, injectable GitHub HTTPS boundary. Response bodies stay in memory."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
import json
import math
import re
import time
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import (CommitSummary, EventPage, QueueItem, Repository, SearchPage,
                     SearchResult, TreeEntry)


class GitHubClientError(RuntimeError):
    """A sanitized transport, validation, or API failure."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class AuthenticationError(GitHubClientError):
    """Authentication or authorization failed (not a rate limit)."""


class RateLimitError(GitHubClientError):
    def __init__(self, retry_after: float):
        super().__init__("GitHub rate limit reached")
        self.retry_after = retry_after


class TruncatedTreeError(GitHubClientError):
    """The API returned an incomplete tree; do not claim a complete scan."""


@dataclass(frozen=True)
class PublicEventPage(EventPage):
    pushes: tuple[QueueItem, ...] = ()


@dataclass(frozen=True)
class RepositorySearchPage:
    items: tuple[Repository, ...]
    total_count: int
    has_next: bool


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Even same-host redirects are rejected: auth never reaches another URL.
        return None


_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


def _text(value, *, limit=4096, empty=False):
    if (not isinstance(value, str) or len(value) > limit or
            (not value and not empty) or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise GitHubClientError("Invalid GitHub string field")
    return value


def _integer(value, minimum=0):
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise GitHubClientError("Invalid GitHub integer field")
    return value


def _object(value):
    if not isinstance(value, dict):
        raise GitHubClientError("Invalid GitHub object")
    return value


def _array(value, limit=10000):
    if not isinstance(value, list) or len(value) > limit:
        raise GitHubClientError("Invalid or oversized GitHub list")
    return value


def _sha(value):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise GitHubClientError("Invalid GitHub commit or object SHA")
    return value.lower()


def _repo_parts(owner, name):
    if (not isinstance(owner, str) or not _OWNER.fullmatch(owner) or
            not isinstance(name, str) or not _REPO.fullmatch(name) or name in {".", ".."}):
        raise GitHubClientError("Invalid GitHub repository name")
    return f"/repos/{owner}/{name}"


def _full_name(value):
    value = _text(value, limit=140)
    parts = value.split("/")
    if len(parts) != 2:
        raise GitHubClientError("Invalid GitHub repository identity")
    _repo_parts(*parts)
    return value


def _file_path(value):
    value = _text(value)
    if value.startswith("/") or "\\" in value or any(p in {"", ".", ".."} for p in value.split("/")):
        raise GitHubClientError("Invalid GitHub file path")
    return value


def _ref(value):
    value = _text(value, limit=1024)
    if ("\\" in value or any(p in {"", ".", ".."} for p in value.split("/") ) or
            any(c in value for c in ":?#[]~^*" ) or any(c.isspace() for c in value)):
        raise GitHubClientError("Invalid GitHub ref")
    return value


def _repository(value, expected=None):
    value = _object(value)
    full_name = _full_name(value.get("full_name"))
    if value.get("private") is not False or value.get("visibility", "public") != "public":
        raise GitHubClientError("Repository is not explicitly public")
    if expected is not None and full_name.lower() != expected.lower():
        raise GitHubClientError("GitHub repository identity mismatch")
    owner = _text(_object(value.get("owner")).get("login"), limit=39)
    if owner.lower() != full_name.split("/")[0].lower():
        raise GitHubClientError("GitHub repository owner mismatch")
    return Repository(full_name, _ref(value.get("default_branch")), owner)


class GitHubClient:
    def __init__(self, token: str | None = None, *, transport=None, timeout=15.0,
                 max_response_bytes=2_000_000, max_retries=2, max_retry_delay=60.0,
                 sleeper: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time, max_file_bytes=512_000,
                 max_tree_entries=10_000, max_patch_bytes=512_000):
        if (not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or
                not 0 < timeout <= 300 or not isinstance(max_retry_delay, (int, float)) or
                not math.isfinite(max_retry_delay) or not 0 <= max_retry_delay <= 3600):
            raise ValueError("Invalid timeout or retry delay")
        if not isinstance(max_retries, int) or isinstance(max_retries, bool) or not 0 <= max_retries <= 10:
            raise ValueError("Invalid retry count")
        for bound in (max_response_bytes, max_file_bytes, max_tree_entries, max_patch_bytes):
            if not isinstance(bound, int) or isinstance(bound, bool) or bound < 1:
                raise ValueError("Invalid response bound")
        if token is not None and (not isinstance(token, str) or not token or
                                  not re.fullmatch(r"[A-Za-z0-9_.-]+", token)):
            raise ValueError("Invalid authentication token")
        self._token = token
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_retries = max_retries
        self.max_retry_delay = max_retry_delay
        self.max_file_bytes = max_file_bytes
        self.max_tree_entries = max_tree_entries
        self.max_patch_bytes = max_patch_bytes
        self._sleep, self._clock = sleeper, clock
        self._opener = build_opener(_NoRedirect())
        self._transport = transport or self._https_transport

    def _https_transport(self, request, timeout):
        try:
            response = self._opener.open(request, timeout=timeout)
        except HTTPError as error:
            response = error
        with response:
            # Inspect a byte beyond the bound, never read an unbounded body.
            body = response.read(self.max_response_bytes + 1)
            if len(body) > self.max_response_bytes:
                raise GitHubClientError("GitHub response exceeds size limit")
            return response.code, dict(response.headers.items()), body

    def _retry_delay(self, headers, attempt):
        delays = []
        retry = headers.get("retry-after")
        if retry is not None:
            try:
                seconds = float(retry)
            except ValueError:
                try:
                    seconds = parsedate_to_datetime(retry).timestamp() - self._clock()
                except (TypeError, ValueError, OverflowError):
                    seconds = -1
            if math.isfinite(seconds) and seconds >= 0:
                delays.append(seconds)
        if headers.get("x-ratelimit-remaining") == "0":
            try:
                seconds = float(headers.get("x-ratelimit-reset", "")) - self._clock()
            except ValueError:
                seconds = -1
            if math.isfinite(seconds) and seconds >= 0:
                delays.append(seconds)
        return max(delays) if delays else float(2 ** attempt)

    def request(self, method: str, path: str, params: Mapping[str, str] | None = None) -> object:
        if method != "GET":
            raise GitHubClientError("Only read-only GitHub requests are supported")
        path = _text(path)
        decoded = unquote(path)
        if (not path.startswith("/") or path.startswith("//") or
                any(c in path for c in "?#\\") or any(c in decoded for c in "?#\\%") or
                any(ord(c) < 32 or ord(c) == 127 for c in decoded) or
                any(p in {".", ".."} for p in decoded.split("/"))):
            raise GitHubClientError("Invalid GitHub API path")
        if params is not None:
            if not isinstance(params, Mapping) or len(params) > 20:
                raise GitHubClientError("Invalid GitHub query parameters")
            for key, value in params.items():
                _text(key, limit=100)
                if not isinstance(value, (str, int)) or isinstance(value, bool):
                    raise GitHubClientError("Invalid GitHub query value")
                _text(str(value), empty=True)
        url = "https://api.github.com" + path
        if params:
            url += "?" + urlencode(params)
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "public-repository-scanner", "Accept-Encoding": "identity"}
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        for attempt in range(self.max_retries + 1):
            try:
                status, response_headers, body = self._transport(Request(url, headers=headers, method=method), self.timeout)
            except (URLError, OSError, TimeoutError):
                if attempt == self.max_retries:
                    raise GitHubClientError("GitHub transport failed") from None
                self._sleep(min(float(2 ** attempt), self.max_retry_delay))
                continue
            if (not isinstance(status, int) or isinstance(status, bool) or not isinstance(body, bytes) or
                    not isinstance(response_headers, dict) or
                    any(not isinstance(k, str) or not isinstance(v, str) for k, v in response_headers.items())):
                raise GitHubClientError("Invalid transport response")
            if len(body) > self.max_response_bytes:
                raise GitHubClientError("GitHub response exceeds size limit")
            normalized = {k.lower(): v for k, v in response_headers.items()}
            limited = status == 429 or (status == 403 and (
                normalized.get("x-ratelimit-remaining") == "0" or "retry-after" in normalized))
            if limited or status in {500, 502, 503, 504}:
                delay = self._retry_delay(normalized, attempt)
                if attempt == self.max_retries or delay > self.max_retry_delay:
                    if limited:
                        raise RateLimitError(delay)
                    raise GitHubClientError("GitHub temporarily unavailable")
                self._sleep(delay)
                continue
            if status in {401, 403}:
                raise AuthenticationError("GitHub authentication or authorization failed")
            if not 200 <= status < 300:
                raise GitHubClientError(f"GitHub HTTP status {status}", status_code=status)
            if status == 204:
                return None
            try:
                return json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                raise GitHubClientError("Invalid GitHub JSON response") from None
        raise GitHubClientError("GitHub request failed")

    def _search(self, endpoint, query, page, per_page):
        _text(query)
        if not 1 <= _integer(page, 1) <= math.ceil(1000 / _integer(per_page, 1)) or per_page > 100:
            raise GitHubClientError("Search page exceeds GitHub result window")
        payload = _object(self.request("GET", endpoint, {"q": query, "page": page, "per_page": per_page}))
        total = _integer(payload.get("total_count"))
        if payload.get("incomplete_results") is not False:
            raise GitHubClientError("GitHub search results are incomplete")
        items = _array(payload.get("items"), per_page)
        return items, total, page * per_page < min(total, 1000) and len(items) == per_page

    def search_code(self, query: str, page: int = 1, per_page: int = 100) -> SearchPage:
        raw, total, has_next = self._search("/search/code", query, page, per_page)
        results = []
        for item in raw:
            item = _object(item)
            repo = _object(item.get("repository"))
            name = _full_name(repo.get("full_name"))
            if repo.get("private") is not False or repo.get("visibility", "public") != "public":
                raise GitHubClientError("Search repository is not explicitly public")
            path = _file_path(item.get("path"))
            blob_sha = _sha(item.get("sha"))  # This is a BLOB SHA, never a commit SHA.
            url = _text(item.get("html_url"))
            parsed = urlsplit(url)
            prefix = "/" + name + "/blob/"
            expected_path = prefix + blob_sha + "/" + path
            if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment or
                    unquote(parsed.path) != expected_path):
                raise GitHubClientError("Invalid GitHub search result URL")
            branch = repo.get("default_branch")
            if branch is None:
                branch = self.repository(*name.split("/")).default_branch
            results.append(SearchResult(name, path, _ref(branch), "", url))
        return SearchPage(tuple(results), total, has_next)

    def search_repositories(self, query: str, page: int = 1, per_page: int = 100) -> RepositorySearchPage:
        raw, total, has_next = self._search("/search/repositories", query, page, per_page)
        return RepositorySearchPage(tuple(_repository(item) for item in raw), total, has_next)

    def list_public_events(self, cursor: str | None = None) -> EventPage:
        if cursor is not None and (not isinstance(cursor, str) or not re.fullmatch(r"[1-9][0-9]*", cursor)):
            raise GitHubClientError("Invalid public events cursor")
        page = int(cursor) if cursor is not None else 1
        if page > 10:
            raise GitHubClientError("Public events history exceeds API window")
        events = _array(self.request("GET", "/events", {"page": page, "per_page": 100}), 100)
        names, pushes = [], []
        for event in events:
            event = _object(event)
            if event.get("public") is not True:
                raise GitHubClientError("Event is not explicitly public")
            name = _full_name(_object(event.get("repo")).get("name"))
            if name not in names:
                names.append(name)
            if event.get("type") == "PushEvent":
                payload = _object(event.get("payload"))
                ref = _ref(payload.get("ref"))
                commits = _array(payload.get("commits", []), 100)
                shas = [_sha(_object(commit).get("sha")) for commit in commits]
                if payload.get("head") is not None:
                    head = _sha(payload["head"])
                    if head != "0" * 40 and head not in shas:
                        shas.append(head)
                pushes.extend(QueueItem(name, ref, sha) for sha in dict.fromkeys(shas) if sha != "0" * 40)
        return PublicEventPage(tuple(names), str(page + 1) if len(events) == 100 and page < 10 else None,
                               tuple(pushes))

    def repository(self, owner: str, name: str) -> Repository:
        return _repository(self.request("GET", _repo_parts(owner, name)), f"{owner}/{name}")

    def tree(self, owner: str, name: str, ref: str) -> list[TreeEntry]:
        payload = _object(self.request("GET", _repo_parts(owner, name) + "/git/trees/" + quote(_ref(ref), safe=""),
                                       {"recursive": "1"}))
        if payload.get("truncated") is not False:
            raise TruncatedTreeError("GitHub tree is truncated or completeness is unknown")
        entries = []
        for item in _array(payload.get("tree"), self.max_tree_entries):
            item = _object(item)
            kind = item.get("type")
            if kind not in {"blob", "tree", "commit"}:
                raise GitHubClientError("Invalid GitHub tree entry type")
            entries.append(TreeEntry(_file_path(item.get("path")), kind,
                                     _integer(item.get("size", 0)), _sha(item.get("sha"))))
        return entries

    def content(self, owner: str, name: str, path: str, ref: str) -> str:
        payload = _object(self.request("GET", _repo_parts(owner, name) + "/contents/" + quote(_file_path(path), safe="/"),
                                       {"ref": _ref(ref)}))
        if (payload.get("type") != "file" or payload.get("encoding") != "base64" or
                _file_path(payload.get("path")) != path or _integer(payload.get("size")) > self.max_file_bytes):
            raise GitHubClientError("Unsupported or oversized GitHub content")
        encoded = payload.get("content")
        if not isinstance(encoded, str) or len(encoded) > (self.max_file_bytes * 2 + 100):
            raise GitHubClientError("Invalid GitHub base64 content")
        try:
            decoded = base64.b64decode(encoded.replace("\n", "").replace("\r", ""), validate=True)
            if len(decoded) > self.max_file_bytes or len(decoded) != payload["size"]:
                raise GitHubClientError("GitHub content size mismatch")
            return decoded.decode("utf-8")
        except (ValueError, UnicodeError, binascii.Error):
            raise GitHubClientError("Invalid or non-text GitHub content") from None

    def resolve_commit(self, owner: str, name: str, ref: str) -> str:
        payload = _object(self.request("GET", _repo_parts(owner, name) + "/commits/" + quote(_ref(ref), safe="")))
        return _sha(payload.get("sha"))

    def commits(self, owner: str, name: str, since: str | None = None, *, limit: int = 10,
                ref: str | None = None) -> list[CommitSummary]:
        base = _repo_parts(owner, name)
        if not 1 <= _integer(limit, 1) <= 1000:
            raise GitHubClientError("Invalid commit history limit")
        params = {}
        if since is not None:
            try:
                if datetime.fromisoformat(_text(since).replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError
            except ValueError:
                raise GitHubClientError("Invalid commit history date") from None
            params["since"] = since
        if ref is not None:
            params["sha"] = _ref(ref)
        result = []
        for page in range(1, math.ceil(limit / 100) + 1):
            count = min(100, limit - len(result))
            raw = _array(self.request("GET", base + "/commits", {**params, "page": page, "per_page": count}), count)
            for item in raw:
                item = _object(item)
                commit = _object(item.get("commit"))
                message = commit.get("message")
                if not isinstance(message, str) or len(message) > 65536:
                    raise GitHubClientError("Invalid GitHub commit message")
                date = _object(commit.get("committer")).get("date")
                if date is not None:
                    _text(date, limit=64)
                    try:
                        if datetime.fromisoformat(date.replace("Z", "+00:00")).tzinfo is None:
                            raise ValueError
                    except ValueError:
                        raise GitHubClientError("Invalid GitHub commit date") from None
                result.append(CommitSummary(_sha(item.get("sha")), message, date))
            if len(raw) < count or len(result) == limit:
                break
        return result

    def commit_files(self, owner: str, name: str, sha: str, *, max_files: int = 3000) -> list[dict]:
        base = _repo_parts(owner, name) + "/commits/" + _sha(sha)
        if not 1 <= _integer(max_files, 1) <= 3000:
            raise GitHubClientError("Invalid commit file limit")
        result, patch_bytes = [], 0
        for page in range(1, math.ceil(max_files / 100) + 1):
            payload = _object(self.request("GET", base, {"page": page, "per_page": 100}))
            if _sha(payload.get("sha")) != sha.lower():
                raise GitHubClientError("GitHub commit identity mismatch")
            raw = _array(payload.get("files"), 100)
            for item in raw:
                item = _object(item)
                if len(result) >= max_files:
                    raise GitHubClientError("GitHub commit file limit exceeded")
                status = item.get("status")
                if status not in {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"}:
                    raise GitHubClientError("Invalid GitHub file status")
                safe = {"filename": _file_path(item.get("filename")), "status": status,
                        "sha": _sha(item.get("sha"))}
                for field in ("additions", "deletions", "changes"):
                    safe[field] = _integer(item.get(field))
                if "previous_filename" in item:
                    safe["previous_filename"] = _file_path(item["previous_filename"])
                if "patch" in item:
                    patch = item["patch"]
                    if not isinstance(patch, str):
                        raise GitHubClientError("Invalid GitHub patch")
                    patch_bytes += len(patch.encode("utf-8"))
                    if patch_bytes > self.max_patch_bytes:
                        raise GitHubClientError("GitHub patch memory limit exceeded")
                    safe["patch"] = patch
                result.append(safe)
            if len(raw) < 100:
                return result
        raise GitHubClientError("GitHub commit files may be truncated")
