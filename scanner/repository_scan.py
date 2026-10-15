"""Bounded, in-memory scanning of public repository snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import PurePosixPath
import re
from typing import Any
from urllib.parse import quote

from .config import Config
from .detector import detect_candidates
from .models import Candidate, FindingRecord, QueueItem, TreeEntry


# A deliberately fixed upper bound keeps one hostile tree from turning into an
# unbounded content-fetch job.  Configurable scan limits remain authoritative too.
MAX_FILES_PER_SCAN = 100
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SKIP_PARTS = {".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "dist", "build", "target"}
_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".jar", ".class", ".exe", ".dll", ".so", ".woff", ".woff2", ".mp3", ".mp4", ".mov"}
_KNOWN_EXTENSIONLESS = {"config", "settings", "secrets", "credentials", "dockerfile", "makefile"}


def select_candidate_files(tree: list[TreeEntry], config: Config) -> list[TreeEntry]:
    """Return a deterministic, bounded list of likely text files from a tree."""
    selected: list[TreeEntry] = []
    seen: set[str] = set()
    # A large response is still safe to inspect, but only its configured prefix
    # is considered.  The fixed cap also bounds work when config is very large.
    for entry in tree[: config.scan.max_tree_entries]:
        if len(selected) >= MAX_FILES_PER_SCAN:
            break
        path = entry.path.replace("\\", "/")
        if entry.entry_type != "blob" or not path or path in seen:
            continue
        if entry.size < 0 or entry.size > config.scan.max_file_size:
            continue
        parts = {part.lower() for part in PurePosixPath(path).parts}
        if parts & _SKIP_PARTS:
            continue
        lower = path.lower()
        if any(lower.endswith(suffix) for suffix in _SKIP_SUFFIXES) or lower.endswith((".min.js", ".min.css", ".map")):
            continue
        name = PurePosixPath(path).name.lower()
        extension_ok = any(lower.endswith(extension.lower()) for extension in config.scan.allowed_extensions)
        env_ok = (name == ".env" or name.startswith(".env.")) and any(
            extension.lower() == ".env" for extension in config.scan.allowed_extensions
        )
        candidate_name = name in _KNOWN_EXTENSIONLESS
        if not (extension_ok or env_ok or candidate_name):
            continue
        seen.add(path)
        selected.append(entry)
    return selected


def scan_queue_item(client: Any, item: QueueItem, config: Config, key: bytes) -> list[FindingRecord]:
    """Scan a queue item and return only safe finding records.

    Source text and complete candidates exist only in local variables.  A direct
    path is intentionally resolved to the current immutable commit instead of
    trusting the search result's blob SHA.
    """
    if not key:
        raise ValueError("fingerprint key must not be empty")
    if not _REPOSITORY.fullmatch(item.repository) or any(part in {".", ".."} for part in item.repository.split("/")):
        raise ValueError("repository must be OWNER/NAME")
    owner, name = item.repository.split("/", 1)
    repository = client.repository(owner, name)
    if getattr(repository, "private", False) or getattr(repository, "visibility", "public") not in {"public", None}:
        raise ValueError("only public repositories may be scanned")

    commit_sha = _resolve_snapshot(client, owner, name, item.ref, item.commit_sha, bool(item.path))
    if item.path:
        paths = [item.path]
    else:
        paths = [entry.path for entry in select_candidate_files(client.tree(owner, name, commit_sha), config)]

    records: dict[tuple[str, str, int, str], FindingRecord] = {}
    scanned_files = _scan_snapshot(client, item.repository, item.ref, commit_sha, paths, config, key, records,
                                   MAX_FILES_PER_SCAN)

    if config.scan.include_history:
        commits = client.commits(owner, name, since=None)
        for summary in commits[: config.broad.max_commits_per_repository]:
            historic_sha = getattr(summary, "sha", "")
            if not _SHA.fullmatch(historic_sha) or historic_sha == commit_sha:
                continue
            historic_tree = client.tree(owner, name, historic_sha)
            historic_paths = [entry.path for entry in select_candidate_files(historic_tree, config)]
            remaining = MAX_FILES_PER_SCAN - scanned_files
            if remaining <= 0:
                break
            scanned_files += _scan_snapshot(client, item.repository, item.ref, historic_sha, historic_paths,
                                            config, key, records, remaining)
    return sorted(records.values(), key=lambda finding: (finding.repository, finding.path, finding.commit_sha, finding.line_number))


def _resolve_snapshot(client: Any, owner: str, name: str, ref: str, supplied_sha: str, direct_path: bool) -> str:
    # Direct search matches may carry a blob SHA, so resolve their ref.  A
    # repository queue item without a direct path already carries its pinned
    # commit when available.
    resolved = client.resolve_commit(owner, name, ref) if direct_path or not supplied_sha else supplied_sha
    if not isinstance(resolved, str) or not _SHA.fullmatch(resolved):
        raise ValueError("GitHub client returned a non-immutable commit SHA")
    return resolved


def _scan_snapshot(client: Any, repository: str, ref: str, commit_sha: str, paths: list[str], config: Config,
                   key: bytes, records: dict[tuple[str, str, int, str], FindingRecord], budget: int) -> int:
    owner, name = repository.split("/", 1)
    scanned = 0
    for path in paths[:budget]:
        scanned += 1
        try:
            source = client.content(owner, name, path, commit_sha)
        except Exception as exc:
            if _is_missing_file(exc):
                continue
            raise
        if not isinstance(source, str) or len(source.encode("utf-8", errors="replace")) > config.scan.max_file_size:
            continue
        if "\x00" in source:
            continue
        for candidate in detect_candidates(source, path, config.detection.confidence_threshold):
            finding = _finding_from_candidate(candidate, repository, ref, commit_sha, path, key)
            merge_key = (finding.path, finding.commit_sha, finding.line_number, finding.fingerprint)
            existing = records.get(merge_key)
            records[merge_key] = _merge_findings(existing, finding) if existing else finding
    return scanned


def _is_missing_file(exc: Exception) -> bool:
    if isinstance(exc, FileNotFoundError):
        return True
    status = getattr(exc, "status", getattr(exc, "status_code", None))
    return status == 404


def _finding_from_candidate(candidate: Candidate, repository: str, ref: str, commit_sha: str, path: str,
                            key: bytes) -> FindingRecord:
    fingerprint = hmac.new(key, candidate.value.encode("utf-8"), hashlib.sha256).hexdigest()
    identity = "\0".join((repository, path, commit_sha, str(candidate.line_number), fingerprint))
    finding_id = hmac.new(key, identity.encode("utf-8"), hashlib.sha256).hexdigest()
    permalink = f"https://github.com/{quote(repository, safe='/')}/blob/{commit_sha}/{quote(path, safe='/')}#L{candidate.line_number}"
    return FindingRecord(
        finding_id=finding_id,
        provider=candidate.provider,
        confidence=candidate.confidence,
        repository=repository,
        ref=ref,
        commit_sha=commit_sha,
        path=path,
        line_number=candidate.line_number,
        permalink=permalink,
        masked_preview=candidate.masked_preview,
        fingerprint=fingerprint,
        rule_ids=candidate.rule_ids,
        evidence=candidate.evidence,
        discovered_at=datetime.now(timezone.utc).isoformat(),
    )


def _merge_findings(existing: FindingRecord, candidate: FindingRecord) -> FindingRecord:
    # Prefer provider-specific matches while retaining the generic evidence that
    # corroborated the same line/value.
    generic = "Unknown API credential"
    provider = candidate.provider if existing.provider == generic else existing.provider
    if existing.provider == generic and candidate.provider == generic:
        provider = generic
    preferred = candidate if candidate.confidence > existing.confidence else existing
    return FindingRecord(
        finding_id=existing.finding_id,
        provider=provider,
        confidence=max(existing.confidence, candidate.confidence),
        repository=existing.repository, ref=existing.ref, commit_sha=existing.commit_sha,
        path=existing.path, line_number=existing.line_number, permalink=existing.permalink,
        masked_preview=preferred.masked_preview, fingerprint=existing.fingerprint,
        rule_ids=tuple(dict.fromkeys(existing.rule_ids + candidate.rule_ids)),
        evidence=tuple(dict.fromkeys(existing.evidence + candidate.evidence)),
        discovered_at=existing.discovered_at,
        status=existing.status,
    )
