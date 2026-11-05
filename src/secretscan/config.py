from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from .models import Finding

CONFIG_NAME = ".secretscan.toml"


@dataclass(frozen=True)
class Config:
    path_globs: tuple[str, ...] = ()
    secret_regexes: tuple[re.Pattern[str], ...] = ()

    def allows(self, f: Finding) -> bool:
        if any(fnmatch(f.path, g) for g in self.path_globs):
            return True
        return any(rx.search(f.secret) for rx in self.secret_regexes)


def load_config(root: Path) -> Config:
    file = root / CONFIG_NAME
    if not file.is_file():
        return Config()
    allow = tomllib.loads(file.read_text()).get("allowlist", {})
    return Config(
        path_globs=tuple(allow.get("paths", ())),
        secret_regexes=tuple(re.compile(r) for r in allow.get("regexes", ())),
    )
