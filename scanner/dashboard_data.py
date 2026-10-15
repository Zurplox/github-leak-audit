"""Safe, JSON-ready transforms used by the local dashboard API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .models import FindingRecord


_SAFE_FINDING_FIELDS = (
    "finding_id", "provider", "confidence", "repository", "ref", "commit_sha",
    "path", "line_number", "permalink", "masked_preview", "fingerprint",
    "rule_ids", "evidence", "discovered_at", "status",
)


def findings_payload(
    findings: Iterable[FindingRecord], page: int, page_size: int, total: int
) -> dict:
    """Build a bounded page response containing only FindingRecord fields.

    Storage normally supplies an already paged iterable.  Accepting a complete
    iterable too keeps this pure helper useful in tests and other local callers.
    """
    _validate_pagination(page, page_size)
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise ValueError("total must be a non-negative integer")
    values = list(findings)
    if len(values) > page_size:
        values = values[(page - 1) * page_size: page * page_size]
    return {
        "data": [_safe_finding(value) for value in values],
        "page": page,
        "pageSize": page_size,
        "totalItems": total,
    }


def summary_payload(findings: Iterable[FindingRecord]) -> dict:
    records = list(findings)
    providers: dict[str, int] = {}
    confidence = {"high": 0, "medium": 0, "low": 0}
    statuses: dict[str, int] = {}
    by_date: dict[str, int] = {}
    for finding in records:
        providers[finding.provider] = providers.get(finding.provider, 0) + 1
        bucket = "high" if finding.confidence >= 80 else "medium" if finding.confidence >= 60 else "low"
        confidence[bucket] += 1
        statuses[finding.status] = statuses.get(finding.status, 0) + 1
        by_date[_utc_date(finding.discovered_at)] = by_date.get(_utc_date(finding.discovered_at), 0) + 1
    return {
        "totalFindings": len(records),
        "providers": dict(sorted(providers.items(), key=lambda item: item[0].casefold())),
        "confidence": confidence,
        "statuses": dict(sorted(statuses.items(), key=lambda item: item[0].casefold())),
        "byDate": dict(sorted(by_date.items())),
    }


def _validate_pagination(page: int, page_size: int) -> None:
    if (not isinstance(page, int) or isinstance(page, bool) or page < 1 or
            not isinstance(page_size, int) or isinstance(page_size, bool) or
            not 1 <= page_size <= 100):
        raise ValueError("page must be positive and page_size must be between 1 and 100")


def _safe_finding(finding: FindingRecord) -> dict:
    if not isinstance(finding, FindingRecord):
        raise ValueError("findings must contain FindingRecord values")
    source = finding.as_dict()
    return {field: source[field] for field in _SAFE_FINDING_FIELDS}


def _utc_date(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).date().isoformat()
    except (TypeError, ValueError, OverflowError):
        return "unknown"
