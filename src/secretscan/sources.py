from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from .models import Chunk

SKIP_DIRS = {
    ".git", ".hg", ".venv", "venv", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
}  # fmt: skip
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    pass


def iter_worktree(root: Path, max_bytes: int = 1_000_000) -> Iterator[Chunk]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]  # prune in place
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            try:
                if p.stat().st_size > max_bytes:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if b"\0" in data[:8192]:  # NUL byte in the first 8 KiB => treat as binary
                continue
            rel = p.relative_to(root).as_posix()
            text = data.decode("utf-8", errors="replace")
            for n, line in enumerate(text.splitlines(), start=1):
                yield Chunk(line, rel, n)


def _git_lines(repo: Path, *args: str) -> Iterator[str]:
    cmd = ["git", "-C", str(repo), "-c", "core.quotepath=off", *args]
    with tempfile.TemporaryFile("w+") as err:  # file, not a pipe: avoids a stderr deadlock
        with subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=err,
            text=True, encoding="utf-8", errors="replace",
        ) as proc:  # fmt: skip
            assert proc.stdout is not None
            for line in proc.stdout:
                yield line.rstrip("\n")
        if proc.returncode:
            err.seek(0)
            raise GitError(err.read().strip() or f"git exited with {proc.returncode}")


def parse_diff(lines: Iterable[str]) -> Iterator[Chunk]:
    commit: str | None = None
    path: str | None = None
    new_line = 0
    in_header = False

    for line in lines:
        if line.startswith("commit:"):
            commit, path, in_header = line[7:], None, False
        elif line.startswith("diff --git "):
            path, in_header = None, True
        elif line.startswith("@@"):
            in_header = False
            m = HUNK_RE.match(line)
            if m:
                new_line = int(m.group(1))
        elif in_header:
            if line.startswith("+++ "):
                target = line[4:].split("\t")[0]
                path = None if target == "/dev/null" else target.removeprefix("b/")
        elif path is not None and line.startswith("+"):
            yield Chunk(line[1:], path, new_line, commit)
            new_line += 1


def iter_staged(repo: Path) -> Iterator[Chunk]:
    yield from parse_diff(
        _git_lines(repo, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff")
    )


def iter_history(repo: Path, revs: tuple[str, ...] = ("--all",)) -> Iterator[Chunk]:
    yield from parse_diff(
        _git_lines(
            repo, "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=commit:%H", *revs
        )
    )