"""Safe JSONL exports and private disclosure drafts."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import urlparse

from .models import FindingRecord


_FINDING_ID = re.compile(r"^[0-9a-f]{64}$")


def write_jsonl(findings: Iterable[FindingRecord], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
            count += 1
    return count


def render_disclosure(finding: FindingRecord, template: str | None = None) -> str:
    permalink = _safe_permalink(finding.permalink)
    values = {
        "finding_id": _md(finding.finding_id),
        "provider": _md(finding.provider),
        "confidence": str(finding.confidence),
        "repository": _md(finding.repository),
        "ref": _md(finding.ref),
        "commit_sha": _md(finding.commit_sha),
        "path": _md(finding.path),
        "line_number": str(finding.line_number),
        "permalink": permalink,
        "masked_preview": _code(finding.masked_preview),
        "fingerprint": _md(finding.fingerprint),
        "rule_ids": _md(", ".join(finding.rule_ids)),
        "evidence": _md(", ".join(finding.evidence)),
        "discovered_at": _md(finding.discovered_at),
        "status": _md(finding.status),
    }
    if template is None:
        template = (Path(__file__).parent / "templates" / "disclosure.md").read_text(encoding="utf-8")
    try:
        return template.format_map(_SafeFormatMap(values))
    except (KeyError, ValueError, IndexError) as exc:
        raise ValueError("invalid disclosure template") from exc


def write_disclosure_draft(finding: FindingRecord, directory: Path) -> Path:
    if not _FINDING_ID.fullmatch(finding.finding_id):
        raise ValueError("finding_id must be exactly 64 lowercase hexadecimal characters")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{finding.finding_id}.md"
    target.write_text(render_disclosure(finding), encoding="utf-8", newline="\n")
    return target


class _SafeFormatMap(dict[str, str]):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)


def _safe_permalink(value: str) -> str:
    if any(ord(character) < 32 or character.isspace() for character in value):
        raise ValueError("permalink contains unsafe whitespace")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("permalink contains an invalid port") from None
    if (parsed.scheme != "https" or parsed.hostname != "github.com" or port is not None or
            parsed.username or parsed.password):
        raise ValueError("permalink must point to github.com over HTTPS")
    return value


def _md(value: str) -> str:
    # Remove controls other than ordinary whitespace, then escape Markdown
    # punctuation so repository-controlled metadata remains inert.
    cleaned = "".join(" " if character in "\n\r\t" else character for character in str(value) if ord(character) >= 32 or character in "\n\r\t")
    for character in r"`*_[]<>#+-.!|(){}":
        cleaned = cleaned.replace(character, "\\" + character)
    return cleaned


def _code(value: str) -> str:
    cleaned = "".join(" " if character in "\n\r\t" else character for character in str(value) if ord(character) >= 32 or character in "\n\r\t")
    return cleaned.replace("`", "'")
