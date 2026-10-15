"""Small, safe data models shared by scanner components."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from typing import Any


@dataclass(frozen=True)
class QueueItem:
    repository: str
    ref: str
    commit_sha: str
    path: str = ""

    @property
    def identity(self) -> str:
        value = "\0".join((self.repository, self.ref, self.commit_sha, self.path))
        return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    provider: str
    confidence: int
    repository: str
    ref: str
    commit_sha: str
    path: str
    line_number: int
    permalink: str
    masked_preview: str
    fingerprint: str
    rule_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    discovered_at: str
    status: str = "open"

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["rule_ids"] = list(self.rule_ids)
        result["evidence"] = list(self.evidence)
        return result


@dataclass(frozen=True)
class TreeEntry:
    path: str
    entry_type: str
    size: int
    sha: str


@dataclass(frozen=True)
class Repository:
    full_name: str
    default_branch: str
    owner_login: str


@dataclass(frozen=True)
class SearchResult:
    repository: str
    path: str
    ref: str
    commit_sha: str
    html_url: str


@dataclass(frozen=True)
class SearchPage:
    items: tuple[SearchResult, ...]
    total_count: int
    has_next: bool


@dataclass(frozen=True)
class EventPage:
    repositories: tuple[str, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class CommitSummary:
    sha: str
    message: str
    committed_at: str | None


@dataclass(frozen=True)
class Candidate:
    provider: str
    confidence: int
    value: str
    line_number: int
    masked_preview: str
    rule_ids: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class FindingContext:
    repository: str
    ref: str
    commit_sha: str
    path: str
    permalink: str
    discovered_at: str
