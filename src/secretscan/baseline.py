from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .models import Finding


def save_baseline(path: Path, findings: Iterable[Finding]) -> int:
    prints = sorted({f.fingerprint for f in findings})
    path.write_text(json.dumps({"version": 1, "fingerprints": prints}, indent=2) + "\n")
    return len(prints)


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text())
    if data.get("version") != 1:
        raise ValueError(f"unsupported baseline version in {path}")
    return set(data["fingerprints"])


def filter_new(findings: Iterable[Finding], known: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint not in known]