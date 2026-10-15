"""In-memory candidate detection and confidence scoring."""

from __future__ import annotations

import math
import re

from .models import Candidate
from .redaction import is_placeholder, mask_secret
from .rules import BEARER_TOKEN, DATABASE_URL, GENERIC_ASSIGNMENT, PROVIDER_RULES, SecretRule


def detect_candidates(text: str, path: str, threshold: int) -> list[Candidate]:
    found: dict[tuple[str, int, str], Candidate] = {}
    for rule in PROVIDER_RULES:
        for match in rule.pattern.finditer(text):
            _add_candidate(found, text, match, rule.provider, rule.confidence, rule.rule_id, rule.evidence, threshold)

    for match in GENERIC_ASSIGNMENT.finditer(text):
        value = match.group("value")
        confidence = _generic_confidence(value, match.group("name"), path)
        _add_candidate(found, text, match, "Unknown API credential", confidence, "generic-assignment", "sensitive assignment", threshold, value)

    for match in BEARER_TOKEN.finditer(text):
        _add_candidate(found, text, match, "Unknown API credential", 70, "bearer-token", "Bearer authorization header", threshold, match.group("value"))

    for match in DATABASE_URL.finditer(text):
        _add_candidate(found, text, match, "Database credential", 76, "database-url", "database connection URL", threshold, match.group("value"))

    return sorted(found.values(), key=lambda candidate: (candidate.line_number, candidate.provider))


def _add_candidate(
    found: dict[tuple[str, int, str], Candidate],
    text: str,
    match: re.Match[str],
    provider: str,
    confidence: int,
    rule_id: str,
    evidence: str,
    threshold: int,
    value: str | None = None,
) -> None:
    value = value or match.group(0)
    value = value.strip("\"'` ,;)")
    if is_placeholder(value) or _looks_like_repeated_test_data(value):
        return
    line_number = text.count("\n", 0, match.start()) + 1
    key = (provider, line_number, value)
    existing = found.get(key)
    candidate = Candidate(
        provider=provider,
        confidence=min(100, confidence),
        value=value,
        line_number=line_number,
        masked_preview=mask_secret(value),
        rule_ids=(rule_id,),
        evidence=(evidence,),
    )
    if candidate.confidence < threshold:
        return
    if existing and existing.confidence >= candidate.confidence:
        return
    found[key] = candidate


def _generic_confidence(value: str, name: str, path: str) -> int:
    score = 62
    if "key" in name.lower() or "token" in name.lower():
        score += 5
    if path.lower().endswith((".env", ".yaml", ".yml", ".toml", ".json")):
        score += 5
    if _entropy(value) >= 3.0:
        score += 5
    return score


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_repeated_test_data(value: str) -> bool:
    return len(set(value)) <= 2 or bool(re.fullmatch(r"(?:0+|1+|abc+|123+)", value.lower()))
