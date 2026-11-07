from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Chunk:
    """One line of text plus where it came from."""

    text: str
    path: str
    line: int
    commit: str | None = None


def redact(secret: str) -> str:
    """Safe-to-print form: first 4 and last 2 characters only."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}…{secret[-2:]}"


def mask_line(text: str, secrets: Iterable[str], width: int = 100) -> str:
    """The source line with every secret replaced by its redacted form, trimmed around the first.

    Masking all secrets on the line (not just the one being reported) keeps one finding's
    context from leaking another finding's value.
    """
    ordered = sorted(set(secrets), key=len, reverse=True)  # longest first: no partial overlaps
    masked = text.strip()
    for s in ordered:
        masked = masked.replace(s, redact(s))
    if len(masked) <= width or not ordered:
        return masked
    hit = masked.find(redact(ordered[-1]))
    start = max(0, hit - width // 4)
    end = min(len(masked), start + width)
    return ("…" if start else "") + masked[start:end] + ("…" if end < len(masked) else "")


@dataclass(frozen=True)
class Finding:
    """A suspected secret. The raw secret is kept out of repr() on purpose."""

    rule_id: str
    description: str
    path: str
    line: int
    secret: str = field(repr=False)
    commit: str | None = None
    confidence: str = "medium"  # "high" | "medium" | "low"
    suggestion: str = ""
    context: str = ""  # the source line with all secrets masked; never raw

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives line shifts: hash of (rule, path, secret)."""
        raw = f"{self.rule_id}:{self.path}:{self.secret}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def redacted(self) -> str:
        return redact(self.secret)
