from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

from . import __version__
from .baseline import filter_new, load_baseline, save_baseline
from .config import load_config
from .engine import scan_chunks
from .reporters import FORMATS
from .sources import GitError, iter_history, iter_staged, iter_worktree

HOOK = "#!/bin/sh\n# installed by secretscan\nexec secretscan scan --staged\n"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secretscan", description=__doc__)
    p.add_argument("--version", action="version", version=f"secretscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan files, staged changes or git history")
    s.add_argument("path", nargs="?", default=".", type=Path)
    mode = s.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan staged changes only")
    mode.add_argument("--history", nargs="*", metavar="REV", default=None,
                      help="scan every commit (optionally limited to revisions, e.g. main~20..HEAD)")
    s.add_argument("--entropy", type=float, metavar="BITS", default=None,
                   help="also flag random-looking tokens at or above this entropy (try 4.5)")
    s.add_argument("--baseline", type=Path, help="ignore findings recorded in this baseline")
    s.add_argument("--write-baseline", type=Path, metavar="FILE",
                   help="record current findings as the baseline and exit 0")
    s.add_argument("--format", choices=sorted(FORMATS), default="text")
    s.add_argument("--output", type=Path, help="write the report here instead of stdout")

    h = sub.add_parser("install-hook", help="install a git pre-commit hook")
    h.add_argument("path", nargs="?", default=".", type=Path)
    h.add_argument("--force", action="store_true", help="overwrite an existing hook")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    root: Path = args.path
    if args.staged:
        chunks = iter_staged(root)
    elif args.history is not None:
        chunks = iter_history(root, tuple(args.history) or ("--all",))
    else:
        chunks = iter_worktree(root)

    config = load_config(root)
    findings = [
        f for f in scan_chunks(chunks, entropy_threshold=args.entropy) if not config.allows(f)
    ]

    if args.write_baseline:
        n = save_baseline(args.write_baseline, findings)
        print(f"Baseline written to {args.write_baseline} ({n} fingerprints).", file=sys.stderr)
        return 0

    if args.baseline:
        findings = filter_new(findings, load_baseline(args.baseline))

    report = FORMATS[args.format](findings)
    if args.output:
        args.output.write_text(report)
    else:
        sys.stdout.write(report)
    return 1 if findings else 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    out = subprocess.run(
        ["git", "-C", str(args.path), "rev-parse", "--git-path", "hooks/pre-commit"],
        capture_output=True, text=True,
    )
    if out.returncode:
        raise GitError(out.stderr.strip())
    hook = Path(out.stdout.strip())
    if not hook.is_absolute():
        hook = args.path / hook
    if hook.exists() and not args.force:
        print(f"{hook} already exists (use --force to overwrite).", file=sys.stderr)
        return 2
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK)
    os.chmod(hook, hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed {hook}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return cmd_scan(args) if args.command == "scan" else cmd_install_hook(args)
    except (GitError, OSError, ValueError) as e:
        print(f"secretscan: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())