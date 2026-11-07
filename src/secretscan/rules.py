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
    confidence: str = "high"  # how likely a match is a real secret: high | medium | low
    advice: str = "Rotate it, then load it from an environment variable or secret manager."


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        group=1,
        advice=(
            "Deactivate this key in IAM and create a new one. Prefer an IAM role or "
            "environment credentials over keys in code."
        ),
    ),
    Rule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        group=1,
        advice=(
            "Revoke it at github.com/settings/tokens and create a new one. Read it from"
            " an environment variable or an Actions secret."
        ),
    ),
    Rule(
        "slack-token",
        "Slack token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        group=1,
        advice=(
            "Revoke the token in your Slack app settings and issue a new one. Keep it "
            "in a secret manager, not in code."
        ),
    ),
    Rule(
        "private-key",
        "Private key block",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        group=1,
        advice=(
            "Treat this key pair as compromised: generate a new one and replace the "
            "public key wherever it was installed. Keep private keys out of the repo."
        ),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        group=1,
        confidence="medium",
        advice=(
            "If this is a live token, revoke the session or rotate the signing key. If "
            "it is a sample, mark the line with `# secretscan:ignore`."
        ),
    ),
    # Unquoted `.env`-style assignment: NAME=<long random-looking value>, whatever NAME is.
    # Entropy >= 4.0 keeps out hex hashes (capped at 4.0), words and paths.
    Rule(
        "env-secret",
        "Unquoted secret assignment",
        re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*([A-Za-z0-9+/_-]{20,})\s*$"),
        group=1,
        min_entropy=4.0,
        confidence="medium",
        advice=(
            "Add the file to .gitignore, commit a .env.example with placeholders "
            "instead, and rotate the value if it was ever committed."
        ),
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
        confidence="low",
        advice=(
            "If it is real, rotate it and load it from the environment. If it is a test"
            " value, allowlist the path in .secretscan.toml or mark the line `# "
            "secretscan:ignore`."
        ),
    ),
)
