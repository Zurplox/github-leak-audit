"""Bounded discovery; durable queue deduplication/checkpointing belongs to the CLI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator
from urllib.parse import unquote, urlsplit

from .config import BroadConfig, SearchConfig
from .models import QueueItem


class SearchDiscovery:
    def __init__(self, client, config: SearchConfig):
        self.client, self.config = client, config

    def discover(self) -> Iterator[QueueItem]:
        # GitHub language qualifiers are alternatives, not an AND across languages.
        # Separate requests also work with the REST legacy search syntax.
        languages = tuple(dict.fromkeys(self.config.languages)) or (None,)
        limit = min(1000, max(0, self.config.max_results_per_query))
        global_seen = set()
        for query in self.config.queries:
            count = 0
            for language in languages:
                if count >= limit:
                    break
                if language is not None:
                    if not language or any(c in language for c in '\r\n"'):
                        raise ValueError("Invalid search language")
                    effective = f'{query} language:"{language}"'
                else:
                    effective = query
                for page in range(1, 11):
                    response = self.client.search_code(effective, page=page)
                    for result in response.items:
                        # Code search's ``sha`` is a blob object. Only preserve a
                        # client-supplied SHA when its URL proves it is an immutable
                        # commit URL; normal search results are always branch work.
                        commit_sha = ""
                        url = getattr(result, "html_url", "")
                        candidate_sha = getattr(result, "commit_sha", "")
                        if isinstance(candidate_sha, str) and len(candidate_sha) == 40 and isinstance(url, str):
                            parsed = urlsplit(url)
                            commit_path = unquote(parsed.path).split("/commit/", 1)
                            if (parsed.scheme == "https" and parsed.netloc == "github.com" and
                                    len(commit_path) == 2 and commit_path[1].split("/", 1)[0].lower() == candidate_sha.lower()):
                                commit_sha = candidate_sha.lower()
                        item = QueueItem(result.repository, result.ref, commit_sha, result.path)
                        if item.identity in global_seen:
                            continue
                        global_seen.add(item.identity)
                        yield item
                        count += 1
                        if count >= limit:
                            break
                    if count >= limit or not response.has_next:
                        break


class BroadDiscovery:
    def __init__(self, client, config: BroadConfig, *, cursor: str | None = None,
                 now: datetime | None = None):
        self.client, self.config = client, config
        self.next_cursor = cursor
        self.now = now

    def discover(self) -> Iterator[QueueItem]:
        maximum = max(0, self.config.max_repositories)
        seen = set()
        now = self.now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("Backfill time must be timezone-aware")
        now = now.astimezone(timezone.utc)
        for _ in range(min(10, max(0, self.config.recent_activity_pages))):
            if len(seen) >= maximum:
                return
            page = self.client.list_public_events(cursor=self.next_cursor)
            self.next_cursor = page.next_cursor
            pushes = getattr(page, "pushes", ())
            for name in page.repositories:
                if name in seen:
                    continue
                if len(seen) >= maximum:
                    return
                repo = self.client.repository(*name.split("/"))
                seen.add(repo.full_name)
                commits = [item for item in pushes if item.repository == name]
                if commits:
                    identities = set()
                    for item in commits:
                        if item.identity not in identities:
                            identities.add(item.identity)
                            yield item
                        if len(identities) >= max(1, self.config.max_commits_per_repository):
                            break
                else:
                    yield QueueItem(repo.full_name, repo.default_branch, "")
            if page.next_cursor is None:
                break
        # Events only expose recent activity (up to 300 events/limited retention).
        # Backfill instead searches repositories CREATED within the chosen date
        # range. It does not pretend to recover historical public events.
        if self.config.backfill_days <= 0 or len(seen) >= maximum:
            return
        start = now - timedelta(days=self.config.backfill_days)
        query = f"is:public created:{start.date().isoformat()}..{now.date().isoformat()}"
        since = start.isoformat().replace("+00:00", "Z")
        for number in range(1, 11):
            page = self.client.search_repositories(query, page=number)
            for repo in page.items:
                if repo.full_name in seen:
                    continue
                if len(seen) >= maximum:
                    return
                seen.add(repo.full_name)
                yield QueueItem(repo.full_name, repo.default_branch, "")
                if self.config.max_commits_per_repository > 0:
                    commits = self.client.commits(*repo.full_name.split("/"), since=since,
                                                  limit=min(1000, self.config.max_commits_per_repository))
                    for commit in commits:
                        yield QueueItem(repo.full_name, repo.default_branch, commit.sha)
            if len(seen) >= maximum or not page.has_next:
                break
