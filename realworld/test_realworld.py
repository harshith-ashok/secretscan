from __future__ import annotations

import json
import subprocess
import time
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

from secretscan.cli import main
from secretscan.config import load_config
from secretscan.engine import scan_chunks
from secretscan.models import Finding
from secretscan.reporters import FORMATS
from secretscan.sources import iter_history

HERE = Path(__file__).parent
CACHE = HERE.parent / ".realworld-cache"
REPORTS = HERE / "reports"
MANIFESTS = (HERE / "repos.toml", HERE / "repos.local.toml")
DEFAULT_MAX_SECONDS = 600.0


@dataclass(frozen=True)
class Repo:
    name: str
    url: str | None = None
    path: str | None = None
    ref: str | None = None
    max_findings: int | None = None
    max_seconds: float = DEFAULT_MAX_SECONDS


def load_repos() -> list[Repo]:
    repos: list[Repo] = []
    for manifest in MANIFESTS:
        if manifest.is_file():
            for entry in tomllib.loads(manifest.read_text()).get("repo", []):
                repos.append(Repo(**entry))
    return repos


def checkout(repo: Repo) -> Path:
    """Return a local directory for the repo: scan `path` in place, or clone/update `url`."""
    if repo.path:
        root = Path(repo.path).expanduser()
        if not root.is_dir():
            pytest.skip(f"{root} does not exist")
        return root
    assert repo.url, f"{repo.name}: set either url or path"
    dest = CACHE / repo.name
    CACHE.mkdir(exist_ok=True)
    cmd = (
        ["git", "-C", str(dest), "fetch", "--quiet", "--all", "--tags"]
        if dest.is_dir()
        else ["git", "clone", "--quiet", repo.url, str(dest)]
    )
    done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode:
        pytest.skip(f"could not fetch {repo.url}: {done.stderr.strip()}")
    return dest


@dataclass(frozen=True)
class Scan:
    repo: Repo
    root: Path
    findings: list[Finding]
    seconds: float


@pytest.fixture(scope="module", params=load_repos(), ids=lambda r: r.name)
def scan(request: pytest.FixtureRequest) -> Scan:
    repo: Repo = request.param
    root = checkout(repo)
    config = load_config(root)
    revs = (repo.ref,) if repo.ref else ("--all",)

    start = time.perf_counter()
    findings = [f for f in scan_chunks(
        iter_history(root, revs)) if not config.allows(f)]
    seconds = time.perf_counter() - start

    by_rule = Counter(f.rule_id for f in findings)
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / f"{repo.name}.json").write_text(
        json.dumps({"seconds": round(seconds, 2),
                   "by_rule": by_rule}, indent=2)
        + "\n"
        + FORMATS["json"](findings)
    )
    print(
        f"\n[{repo.name}] {len(findings)} finding(s) in {seconds:.1f}s {dict(by_rule)}")
    return Scan(repo, root, findings, seconds)


def test_history_scan_finishes_within_budget(scan: Scan) -> None:
    assert scan.seconds <= scan.repo.max_seconds


def test_findings_within_budget(scan: Scan) -> None:
    if scan.repo.max_findings is None:
        pytest.skip("no max_findings set; findings are only recorded")
    assert len(scan.findings) <= scan.repo.max_findings, (
        f"{len(scan.findings)} findings, see realworld/reports/{scan.repo.name}.json"
    )


def test_findings_are_well_formed(scan: Scan) -> None:
    for f in scan.findings:
        # history findings always have a commit
        assert f.path and f.line >= 1 and f.commit


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_no_report_format_leaks_a_raw_secret(scan: Scan, fmt: str) -> None:
    report = FORMATS[fmt](scan.findings)
    leaked = [f.rule_id for f in scan.findings if f.secret in report]
    assert not leaked, f"{len(leaked)} raw secret(s) appear in {fmt} output"


def test_json_and_sarif_are_valid_and_complete(scan: Scan) -> None:
    n = len(scan.findings)
    assert len(json.loads(FORMATS["json"](scan.findings))["findings"]) == n
    sarif = json.loads(FORMATS["sarif"](scan.findings))
    assert len(sarif["runs"][0]["results"]) == n


def test_cli_worktree_scan_does_not_error(scan: Scan, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    code = main(["scan", str(scan.root), "--format",
                "json", "--output", str(out)])
    assert code in (0, 1)  # 2 would mean the scanner itself failed
    json.loads(out.read_text())
