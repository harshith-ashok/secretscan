from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    group: int = 0  # which regex group holds the secret itself
    min_entropy: float | None = None  # drop matches that look too regular


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        group=1,
    ),
    Rule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        group=1,
    ),
    Rule(
        "slack-token",
        "Slack token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        group=1,
    ),
    Rule(
        "private-key",
        "Private key block",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        group=1,
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        group=1,
    ),
    # Most general rule last, so specific rules win when both match the same secret.
    Rule(
        "generic-credential",
        "Hard-coded credential assignment",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
        ),
        group=1,
        min_entropy=3.0,
    ),
)