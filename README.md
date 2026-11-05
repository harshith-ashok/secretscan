<h3 align="center">secretscan</h3>

<p align="center">A staged design for finding leaked secrets in files, staged changes and git history</p>

---

## Abstract

Credentials committed to source control remain exposed after the offending line is deleted, because the line persists in history. `secretscan` is a Python library that separates *where text comes from* (sources), *what counts as a secret* (rules and entropy), and *what is reported* (findings). The three stages communicate only through two small immutable types, `Chunk` and `Finding`. This document describes the current design, the detection method, the evaluation done so far, and the known limitations.

## 1. Architecture

The core design rule is that three independent stages communicate only through small data types.

![architecture](figs/architecture.png)

| Stage | Module | Responsibility |
|---|---|---|
| Sources | [sources.py](src/secretscan/sources.py) | Turn the outside world (disk, git) into `Chunk`s |
| Engine | [engine.py](src/secretscan/engine.py), [rules.py](src/secretscan/rules.py), [entropy.py](src/secretscan/entropy.py) | Turn `Chunk`s into `Finding`s |
| Data types | [models.py](src/secretscan/models.py) | `Chunk` (one line plus origin) and `Finding` (a suspected secret) |

All stages are lazy generators, so memory use does not grow with repository size.

### 1.1 Data types

- **`Chunk(text, path, line, commit=None)`**: a single line and its provenance. `commit` is set only for history scans.
- **`Finding(rule_id, description, path, line, secret, commit)`**: a suspected secret. Two properties are designed to avoid creating a second leak:
  - `secret` is excluded from `repr()`.
  - `redacted` exposes only the first 4 and last 2 characters (fully masked if 8 characters or fewer).
  - `fingerprint` is the first 16 hex characters of SHA-256 over `(rule_id, path, secret)`, stable when lines shift.

## 2. Detection method

![engine](figs/engine.png)

`scan_chunk` applies the following, in order, to each line:

1. **Skip filters.** Lines over 4000 characters (minified code, which also bounds regex cost) and lines containing `secretscan:ignore` are dropped.
2. **Pattern rules.** Each `Rule` is a compiled regex with a capture group for the secret and an optional minimum Shannon entropy.
3. **Placeholder filter.** Matches containing `example`, `changeme`, `your_`, `<`, `xxxx`, `placeholder` or `dummy` (case-insensitive) are discarded.
4. **Deduplication.** A secret already reported on the line is not reported again. Rule order matters, so specific rules are listed before the general one and win when both match.
5. **Entropy detector (opt-in).** If `entropy_threshold` is given, tokens of 20 or more characters from the base64 or URL-safe alphabet are flagged when their entropy meets the threshold.

### 2.1 Built-in rules

| Rule id | Target | Notes |
|---|---|---|
| `aws-access-key-id` | `AKIA…` / `ASIA…` plus 16 `[0-9A-Z]` | |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` plus 36 or more alphanumerics | |
| `slack-token` | `xox[baprs]-…` | |
| `private-key` | PEM header (`RSA`, `EC`, `DSA`, `OPENSSH` or bare) | Matches the header line only |
| `jwt` | Three base64url segments, the first two starting `eyJ` | |
| `generic-credential` | `api_key`, `secret`, `token`, `passwd`, `password` assigned a quoted value of 8 or more characters | Requires entropy of at least 3.0 bits per character |

### 2.2 Entropy

Shannon entropy is computed per character as H = −Σ pᵢ log₂ pᵢ ([entropy.py](src/secretscan/entropy.py)). Entropy is bounded by log₂ of the alphabet size, so the threshold interacts with the alphabet. A hex string such as a git SHA can never exceed 4.0 bits per character. A threshold above 4.0 therefore excludes hex identifiers by construction, and a test asserts this. The default for the generic rule (3.0) rejects repetitive values like `aaaaaaaa`.

## 3. Sources

![sources](figs/sources.png)

Sources turn the outside world into `Chunk`s. Three of them share one diff parser.

| Source | Function | Input |
|---|---|---|
| Working tree | `iter_worktree(root, max_bytes=1_000_000)` | Files on disk |
| Staged changes | `iter_staged(repo)` | `git diff --cached -U0` |
| History | `iter_history(repo, revs=("--all",))` | `git log -p -U0 --format=commit:%H` |

**Working tree.** The walk prunes `.git`, `.hg`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `dist` and `build`. It skips symlinks, unreadable files, files over `max_bytes`, and files with a NUL byte in the first 8 KiB (treated as binary). Undecodable bytes are replaced rather than raising.

**Diff-based sources.** `parse_diff` is a small state machine over unified-diff output. It tracks the commit, the target path (from `+++`, with `/dev/null` meaning a deletion), and the new-side line number from each `@@` hunk header. Only added lines (`+`) become chunks, so removed lines are never reported. A `+++` line inside a hunk is treated as content, not as a header.

**Git invocation.** Git runs as a subprocess with `core.quotepath=off`. stderr goes to a temporary file instead of a pipe to avoid a deadlock on large output, and a non-zero exit raises `GitError` with git's message.

## 4. Evaluation

Evaluation consists of a unit and property test suite.

```
uv run pytest -q   →   19 passed
```

| Test file | Covers |
|---|---|
| [test_engine.py](tests/test_engine.py) | Per-rule detection with location, inline ignore, placeholders, entropy gating of the generic rule, specific-over-generic precedence, opt-in entropy detector, hex SHA not flagged, secret absent from `repr` and `redacted` |
| [test_entropy.py](tests/test_entropy.py) | Known values (0 bits, 1 bit, 4 bits) and a Hypothesis property: entropy never exceeds log₂ of the number of distinct symbols |
| [test_sources.py](tests/test_sources.py) | Diff parsing (paths, line numbers, commit, `+++` in content, deletions), worktree filtering, staged-only additions, and history containing a line deleted from HEAD |

The history test builds a real temporary git repository. It is the check that justifies having a history mode, since a deleted secret must still be found. Fixture secrets in [conftest.py](tests/conftest.py) are assembled at runtime so the repository does not trip its own scanner.

## 5. Usage (library)

```python
from pathlib import Path
from secretscan.engine import scan_chunks
from secretscan.sources import iter_worktree, iter_staged, iter_history

repo = Path(".")

for f in scan_chunks(iter_history(repo), entropy_threshold=4.5):
    print(f.rule_id, f.path, f.line, f.commit, f.redacted)
```

`entropy_threshold=None` (the default) disables the entropy detector.

## 6. Limitations

- **Line-local matching.** Each line is scanned alone, so multi-line secrets are not detected. For private keys only the `BEGIN` header is matched, not the key body.
- **Fixed rule set.** Only the six rules above exist.
- **Heuristic filters.** The placeholder filter is substring-based, so a real secret containing `<` or `example` is silently dropped. `secretscan:ignore` suppresses everything on its line.
- **Entropy ambiguity.** The entropy detector does not distinguish random secrets from other high-entropy strings such as hashes in base64, and it has no allowlist.
- **History scope.** History scanning reads only added lines from `git log -p`. Merge commits are not shown with a diff by default, and renamed or binary content is not examined.
- **Size limits.** Files over 1 MB and lines over 4000 characters are skipped, which can hide a secret in a large file.

## 7. Reproducing

Requires Python 3.10 or newer and `git` on `PATH`. The `.python-version` file pins 3.10.

```bash
uv sync --extra dev
uv run pytest -q
```

`pytest` also works directly in any environment with `pytest` and `hypothesis` installed (`pythonpath = ["src"]` is set in [pyproject.toml](pyproject.toml)).

Dev extras declared in [pyproject.toml](pyproject.toml): `pytest`, `pytest-cov`, `hypothesis`, `ruff`, `mypy`, `build`. The test suite uses `hypothesis`, so it must be installed. The package has no runtime dependencies.

## License

MIT, as declared in [pyproject.toml](pyproject.toml).
