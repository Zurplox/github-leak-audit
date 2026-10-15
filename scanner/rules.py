"""Provider-specific and generic detection rules."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    provider: str
    pattern: re.Pattern[str]
    confidence: int
    evidence: str


PROVIDER_RULES = (
    SecretRule("stripe-live", "Stripe", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), 92, "Stripe live-key prefix"),
    SecretRule("anthropic-key", "Anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 90, "Anthropic key prefix"),
    SecretRule("openai-key", "OpenAI", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 86, "OpenAI key prefix"),
    SecretRule("github-token", "GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 92, "GitHub token prefix"),
    SecretRule("aws-access-key", "AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 94, "AWS access-key prefix"),
    SecretRule("google-api-key", "Google Cloud", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), 88, "Google API-key prefix"),
    SecretRule("slack-token", "Slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 90, "Slack token prefix"),
    SecretRule("twilio-api-key", "Twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 88, "Twilio key format"),
)


GENERIC_ASSIGNMENT = re.compile(
    r"(?ix)(?<![A-Za-z0-9])(?P<name>(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|token|password))"
    r"(?![A-Za-z0-9])\s*(?:=|:|=>)\s*[\"']?(?P<value>[A-Za-z0-9_./+=:-]{12,})"
)

BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9_./+=:-]{20,})")
DATABASE_URL = re.compile(r"\b(?P<value>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s\"']+)")
