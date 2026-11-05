from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Chunk:
    """One line of text plus where it came from."""

    text: str
    path: str
    line: int
    commit: str | None = None


@dataclass(frozen=True)
class Finding:
    """A suspected secret. The raw secret is kept out of repr() on purpose."""

    rule_id: str
    description: str
    path: str
    line: int
    secret: str = field(repr=False)
    commit: str | None = None

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives line shifts: hash of (rule, path, secret)."""
        raw = f"{self.rule_id}:{self.path}:{self.secret}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def redacted(self) -> str:
        """Safe-to-print form: first 4 and last 2 characters only."""
        if len(self.secret) <= 8:
            return "*" * len(self.secret)
        return f"{self.secret[:4]}…{self.secret[-2:]}"
