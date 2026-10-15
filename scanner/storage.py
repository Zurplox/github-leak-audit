"""Local queue and checkpoint persistence."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
from typing import Iterable

from .models import FindingRecord, QueueItem


class ScanQueue:
    def __init__(self, path: Path, *, read_only: bool = False, recover: bool = True):
        self.path = path
        if read_only:
            self.connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
            self.connection.row_factory = sqlite3.Row
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS queue (
                identity TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                ref TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                claimed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            """
        )
        # This is a single-process local queue. Any in-progress work belongs to
        # the process that disappeared and must be retried after restart.
        if recover:
            self.connection.execute(
                "UPDATE queue SET status = 'pending', claimed_at = NULL WHERE status = 'in_progress'"
            )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def enqueue(self, item: QueueItem) -> bool:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO queue
            (identity, repository, ref, commit_sha, path, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
            """,
            (item.identity, item.repository, item.ref, item.commit_sha, item.path),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def claim(self, limit: int) -> list[QueueItem]:
        if limit < 1:
            return []
        with self.connection:
            rows = self.connection.execute(
                "SELECT * FROM queue WHERE status = 'pending' ORDER BY rowid LIMIT ?",
                (limit,),
            ).fetchall()
            for row in rows:
                self.connection.execute(
                    "UPDATE queue SET status = 'in_progress', claimed_at = datetime('now') WHERE identity = ?",
                    (row["identity"],),
                )
        return [
            QueueItem(row["repository"], row["ref"], row["commit_sha"], row["path"])
            for row in rows
        ]

    def complete(self, identity: str, status: str) -> None:
        if status not in {"done", "failed", "pending"}:
            raise ValueError("invalid queue status")
        self.connection.execute(
            "UPDATE queue SET status = ?, claimed_at = NULL WHERE identity = ?",
            (status, identity),
        )
        self.connection.commit()

    def checkpoint(self, name: str, value: str) -> None:
        self.connection.execute(
            "INSERT INTO checkpoints(name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            (name, value),
        )
        self.connection.commit()

    def get_checkpoint(self, name: str) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM checkpoints WHERE name = ?", (name,)
        ).fetchone()
        return row["value"] if row else None

    def save_finding(self, finding: FindingRecord) -> bool:
        payload = json.dumps(finding.as_dict(), ensure_ascii=False, sort_keys=True)
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO findings(finding_id, payload) VALUES (?, ?)",
            (finding.finding_id, payload),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def list_findings(self) -> list[FindingRecord]:
        rows = self.connection.execute("SELECT payload FROM findings ORDER BY rowid").fetchall()
        return [_finding_from_dict(json.loads(row["payload"])) for row in rows]

    def queue_counts(self) -> dict[str, int]:
        """Return queue counters without exposing queue item metadata."""
        rows = self.connection.execute(
            "SELECT status, COUNT(*) AS count FROM queue GROUP BY status"
        ).fetchall()
        counts = {status: 0 for status in ("pending", "in_progress", "done", "failed")}
        for row in rows:
            if row["status"] in counts:
                counts[row["status"]] = int(row["count"])
        return counts

    def list_findings_page(
        self, page: int, page_size: int, provider: str | None = None
    ) -> tuple[list[FindingRecord], int]:
        """Read a bounded, deterministic page of safe finding records."""
        if (not isinstance(page, int) or isinstance(page, bool) or page < 1 or
                not isinstance(page_size, int) or isinstance(page_size, bool) or
                not 1 <= page_size <= 100):
            raise ValueError("page must be positive and page_size must be between 1 and 100")
        if provider is not None and (not isinstance(provider, str) or len(provider) > 200):
            raise ValueError("provider must be a short string")
        where = ""
        parameters: tuple[object, ...] = ()
        if provider is not None:
            where = " WHERE lower(json_extract(payload, '$.provider')) = lower(?)"
            parameters = (provider,)
        total = int(self.connection.execute(
            "SELECT COUNT(*) AS count FROM findings" + where, parameters
        ).fetchone()["count"])
        offset = min((page - 1) * page_size, total)
        rows = self.connection.execute(
            "SELECT payload FROM findings" + where + " ORDER BY rowid LIMIT ? OFFSET ?",
            parameters + (page_size, offset),
        ).fetchall()
        return [_finding_from_dict(json.loads(row["payload"])) for row in rows], total

    def get_finding(self, finding_id: str) -> FindingRecord | None:
        row = self.connection.execute(
            "SELECT payload FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return _finding_from_dict(json.loads(row["payload"])) if row else None


def _finding_from_dict(value: dict) -> FindingRecord:
    value["rule_ids"] = tuple(value["rule_ids"])
    value["evidence"] = tuple(value["evidence"])
    return FindingRecord(**value)
