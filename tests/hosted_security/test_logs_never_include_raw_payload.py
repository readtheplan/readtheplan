from __future__ import annotations

import re

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[^\s]+"),
    re.compile(r"(?i)password\s*[:=]\s*[^\s]+"),
]

FORBIDDEN_LOG_TOKENS = [
    "raw_plan_json",
    '"resource_changes"',
    '"before"',
    '"after"',
]


def _is_safe_log_line(line: str) -> bool:
    lowered = line.lower()
    if any(token.lower() in lowered for token in FORBIDDEN_LOG_TOKENS):
        return False
    return not any(pattern.search(line) for pattern in SECRET_PATTERNS)


def test_sanitized_log_line_is_allowed() -> None:
    line = "run_id=run_123 tenant=tenant_abc risk_counts=safe:2,review:1"
    assert _is_safe_log_line(line)


def test_raw_payload_log_line_is_rejected() -> None:
    line = 'event=analyze payload={"raw_plan_json":{"resource_changes":[{"before":{}}]}}'
    assert not _is_safe_log_line(line)


def test_secret_like_log_line_is_rejected() -> None:
    line = "aws_secret_access_key=super-secret-value"
    assert not _is_safe_log_line(line)
