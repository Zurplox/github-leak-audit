"""Single cooperative background scan used by the local dashboard."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from threading import Event, Lock, Thread
import sqlite3
from typing import Callable

from .config import Config, ConfigError, RuntimeSecrets
from .discovery import BroadDiscovery, SearchDiscovery
from .github_client import AuthenticationError, GitHubClient, GitHubClientError, RateLimitError
from .models import QueueItem
from .reports import write_disclosure_draft, write_jsonl
from .repository_scan import scan_queue_item
from .storage import ScanQueue


class ScanManagerError(RuntimeError):
    """Base class for dashboard scan lifecycle errors."""


class ScanConflict(ScanManagerError):
    pass


class ScanValidationError(ScanManagerError):
    pass


class ScanConfigurationError(ScanManagerError):
    pass


_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$")
_MODES = frozenset(("search", "broad", "hybrid", "repo"))


class ScanManager:
    def __init__(self, config: Config, *, client_factory: Callable | None = None,
                 queue_factory: Callable | None = None, fingerprint_key: bytes | None = None):
        self.config = config
        self._client_factory = client_factory or self._make_client
        self._queue_factory = queue_factory or ScanQueue
        self._fingerprint_key = fingerprint_key
        self._lock = Lock()
        self._stop = Event()
        self._pause = Event()
        self._thread: Thread | None = None
        self._status = "idle"
        self._mode: str | None = None
        self._repository: str | None = None
        self._started_at: str | None = None
        self._updated_at: str | None = None
        self._last_error: str | None = None
        self._once = False
        self._requests = 0
        queue = self._queue_factory(self.config.reports.state_database)
        queue.close()

    def start(self, mode: str, repository: str | None = None, once: bool = False) -> dict:
        if mode not in _MODES:
            raise ScanValidationError("mode must be search, broad, hybrid, or repo")
        if not isinstance(once, bool):
            raise ScanValidationError("once must be a boolean")
        if mode == "repo":
            if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
                raise ScanValidationError("repo mode requires OWNER/REPO")
        elif repository is not None:
            raise ScanValidationError("repository is only valid for repo mode")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise ScanConflict("a scan is already active")
            try:
                secrets = RuntimeSecrets(self._fingerprint_key, None) if self._fingerprint_key is not None else Config.from_environment()
            except ConfigError as error:
                raise ScanConfigurationError(str(error)) from None
            self._stop = Event()
            self._pause = Event()
            self._status = "running"
            self._mode = mode
            self._repository = repository
            self._once = once
            self._started_at = _now()
            self._updated_at = self._started_at
            self._last_error = None
            self._requests = 0
            self._thread = Thread(target=self._run, args=(mode, repository, once, secrets),
                                  name="scanner-dashboard", daemon=True)
            self._thread.start()
        return self.status()

    def pause(self) -> dict:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                self._pause.set()
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                self._stop.set()
            elif self._status not in {"stopped", "completed", "failed", "idle"}:
                self._status = "stopped"
                self._updated_at = _now()
        return self.status()

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)

    def status(self) -> dict:
        counts = {"pending": 0, "in_progress": 0, "done": 0, "failed": 0}
        findings = 0
        queue = None
        try:
            queue = self._queue_factory(self.config.reports.state_database, read_only=True)
            counts = queue.queue_counts()
            findings = len(queue.list_findings())
        except (OSError, ValueError, sqlite3.Error):
            pass
        finally:
            if queue is not None:
                queue.close()
        with self._lock:
            return {
                "status": self._status,
                "mode": self._mode,
                "repository": self._repository,
                "startedAt": self._started_at,
                "updatedAt": self._updated_at,
                "lastError": self._last_error,
                "counters": {
                    "queued": counts["pending"], "inProgress": counts["in_progress"],
                    "done": counts["done"], "failed": counts["failed"],
                    "findings": findings, "requests": self._requests,
                },
                "continuous": bool(self._mode in {"broad", "hybrid"} and self.config.broad.continuous and not self._once),
                "pollIntervalSeconds": self.config.broad.poll_interval_seconds,
            }

    def _make_client(self, secrets: RuntimeSecrets):
        return GitHubClient(secrets.github_token, max_file_bytes=self.config.scan.max_file_size,
                            max_tree_entries=self.config.scan.max_tree_entries)

    def _run(self, mode: str, repository: str | None, once: bool, secrets: RuntimeSecrets) -> None:
        queue = None
        try:
            queue = self._queue_factory(self.config.reports.state_database, recover=False)
            client = _CountingClient(self._client_factory(secrets), self._increment_requests)
            items = self._discover(client, mode, repository)
            for item in items:
                if self._stop.is_set() or self._pause.is_set():
                    break
                queue.enqueue(item)
            while True:
                if self._stop.is_set():
                    self._finish("stopped")
                    return
                if self._pause.is_set():
                    self._finish("paused")
                    return
                batch = queue.claim(self.config.broad.max_concurrent_scans)
                if not batch:
                    if mode in {"broad", "hybrid"} and self.config.broad.continuous and not once:
                        self._stop.wait(self.config.broad.poll_interval_seconds)
                        if self._stop.is_set():
                            self._finish("stopped")
                            return
                        if self._pause.is_set():
                            self._finish("paused")
                            return
                        for item in self._discover(client, mode, repository):
                            if self._stop.is_set() or self._pause.is_set():
                                self._finish("stopped" if self._stop.is_set() else "paused")
                                return
                            queue.enqueue(item)
                        continue
                    self._finish("completed")
                    return
                for item in batch:
                    if self._stop.is_set() or self._pause.is_set():
                        for pending in batch[batch.index(item):]:
                            queue.complete(pending.identity, "pending")
                        self._finish("stopped" if self._stop.is_set() else "paused")
                        return
                    try:
                        findings = scan_queue_item(client, item, self.config, secrets.fingerprint_key)
                        new_findings = [finding for finding in findings if queue.save_finding(finding)]
                        write_jsonl(new_findings, self.config.reports.output_directory / "findings.jsonl")
                        for finding in new_findings:
                            write_disclosure_draft(finding, self.config.reports.output_directory / "drafts")
                        queue.complete(item.identity, "done")
                    except RateLimitError:
                        queue.complete(item.identity, "pending")
                        self._finish("rate_limited", "GitHub rate limit reached")
                        return
                    except Exception as error:
                        queue.complete(item.identity, "failed")
                        self._finish("failed", _safe_error(error))
                        return
                    if self._stop.is_set() or self._pause.is_set():
                        for pending in batch[batch.index(item) + 1:]:
                            queue.complete(pending.identity, "pending")
                        self._finish("stopped" if self._stop.is_set() else "paused")
                        return
        except RateLimitError:
            self._finish("rate_limited", "GitHub rate limit reached")
        except Exception as error:
            self._finish("failed", _safe_error(error))
        finally:
            if queue is not None:
                queue.close()

    def _discover(self, client, mode: str, repository: str | None):
        if mode == "repo":
            owner, name = repository.split("/", 1)
            found = client.repository(owner, name)
            return (QueueItem(found.full_name, found.default_branch, ""),)
        items = []
        if mode in {"search", "hybrid"}:
            items.extend(SearchDiscovery(client, self.config.search).discover())
        if mode in {"broad", "hybrid"}:
            items.extend(BroadDiscovery(client, self.config.broad).discover())
        return items

    def _increment_requests(self):
        with self._lock:
            self._requests += 1

    def _finish(self, status: str, error: str | None = None) -> None:
        with self._lock:
            self._status = status
            self._last_error = error
            self._updated_at = _now()


class _CountingClient:
    def __init__(self, client, increment):
        self._client, self._increment = client, increment

    def __getattr__(self, name):
        value = getattr(self._client, name)
        if not callable(value):
            return value
        def call(*args, **kwargs):
            self._increment()
            return value(*args, **kwargs)
        return call


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_error(error: Exception) -> str:
    text = "".join(character if ord(character) >= 32 else " " for character in str(error))
    text = re.sub(r"(?i)(?:sk|pk|gh[opsu])_[A-Za-z0-9_-]+", "[redacted]", text)
    return text[:300] or type(error).__name__
