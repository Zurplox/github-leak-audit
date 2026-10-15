"""Configuration loading and runtime secret access."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from typing import Any


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


@dataclass(frozen=True)
class SearchConfig:
    queries: tuple[str, ...] = (
        'filename:.env password',
        'filename:.env API_KEY',
        'filename:config.json token',
        'filename:.yml secret',
    )
    max_results_per_query: int = 100
    languages: tuple[str, ...] = ()


@dataclass(frozen=True)
class BroadConfig:
    continuous: bool = True
    poll_interval_seconds: int = 300
    recent_activity_pages: int = 1
    backfill_days: int = 7
    max_repositories: int = 100
    max_commits_per_repository: int = 10
    max_concurrent_scans: int = 4


@dataclass(frozen=True)
class ScanConfig:
    max_file_size: int = 512_000
    max_tree_entries: int = 10_000
    include_history: bool = True
    allowed_extensions: tuple[str, ...] = (
        ".env", ".ini", ".cfg", ".conf", ".json", ".yaml", ".yml",
        ".toml", ".xml", ".properties", ".py", ".js", ".ts", ".go",
        ".java", ".rb", ".php", ".sh", ".tf", ".txt",
    )


@dataclass(frozen=True)
class DetectionConfig:
    confidence_threshold: int = 60


@dataclass(frozen=True)
class ReportsConfig:
    output_directory: Path = Path("reports")
    state_database: Path = Path("state/scanner.sqlite3")


@dataclass(frozen=True)
class RuntimeSecrets:
    fingerprint_key: bytes
    github_token: str | None = None


@dataclass(frozen=True)
class Config:
    mode: str = "hybrid"
    search: SearchConfig = field(default_factory=SearchConfig)
    broad: BroadConfig = field(default_factory=BroadConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    reports: ReportsConfig = field(default_factory=ReportsConfig)

    @classmethod
    def load(cls, path: Path) -> "Config":
        with path.open("rb") as handle:
            raw = tomllib.load(handle)

        mode = raw.get("mode", "hybrid")
        if mode not in {"search", "broad", "hybrid"}:
            raise ConfigError("mode must be search, broad, or hybrid")

        search_raw = _section(raw, "search")
        broad_raw = _section(raw, "broad")
        scan_raw = _section(raw, "scan")
        detection_raw = _section(raw, "detection")
        reports_raw = _section(raw, "reports")

        max_results = _positive_int(search_raw, "max_results_per_query", 100)
        threshold = _range_int(detection_raw, "confidence_threshold", 60, 0, 100)
        workers = _positive_int(broad_raw, "max_concurrent_scans", 4)
        max_repositories = _positive_int(broad_raw, "max_repositories", 100)
        max_file_size = _positive_int(scan_raw, "max_file_size", 512_000)

        queries = tuple(_string_list(search_raw.get("queries"), SearchConfig().queries))
        languages = tuple(_string_list(search_raw.get("languages"), ()))
        extensions = tuple(_string_list(scan_raw.get("allowed_extensions"), ScanConfig().allowed_extensions))

        return cls(
            mode=mode,
            search=SearchConfig(queries, max_results, languages),
            broad=BroadConfig(
                continuous=bool(broad_raw.get("continuous", True)),
                poll_interval_seconds=_positive_int(broad_raw, "poll_interval_seconds", 300),
                recent_activity_pages=_positive_int(broad_raw, "recent_activity_pages", 1),
                backfill_days=max(0, int(broad_raw.get("backfill_days", 7))),
                max_repositories=max_repositories,
                max_commits_per_repository=_positive_int(broad_raw, "max_commits_per_repository", 10),
                max_concurrent_scans=workers,
            ),
            scan=ScanConfig(
                max_file_size=max_file_size,
                max_tree_entries=_positive_int(scan_raw, "max_tree_entries", 10_000),
                include_history=bool(scan_raw.get("include_history", True)),
                allowed_extensions=extensions,
            ),
            detection=DetectionConfig(threshold),
            reports=ReportsConfig(
                output_directory=Path(reports_raw.get("output_directory", "reports")),
                state_database=Path(reports_raw.get("state_database", "state/scanner.sqlite3")),
            ),
        )

    @classmethod
    def from_environment(cls) -> RuntimeSecrets:
        fingerprint = os.environ.get("SCANNER_FINGERPRINT_KEY")
        if not fingerprint:
            raise ConfigError("SCANNER_FINGERPRINT_KEY must be set")
        return RuntimeSecrets(
            fingerprint_key=fingerprint.encode("utf-8"),
            github_token=os.environ.get("GITHUB_TOKEN"),
        )


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a table")
    return value


def _positive_int(raw: dict[str, Any], name: str, default: int) -> int:
    value = raw.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _range_int(raw: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = raw.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _string_list(value: Any, default: tuple[str, ...]) -> list[str]:
    if value is None:
        return list(default)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError("list values must contain only strings")
    return value
