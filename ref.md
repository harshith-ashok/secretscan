# secretscan: build a git secret scanner in Python

> [!abstract] What you will have at the end
> A zero-dependency Python CLI that finds leaked credentials in **files on disk**, **staged changes** and **entire git history**. It has a rule engine, an entropy detector, baselines and allowlists, text/JSON/**SARIF** output, a pre-commit hook, a test suite, GitHub Actions CI, PyPI + Docker release pipelines and a reusable GitHub Action.

> [!info] How to use this note
> Each step has **Concept → Design → Code → Test → Checkpoint**. Every code block is the real file from the finished project (==nothing is pseudo-code==). Build in order; run the checkpoint before moving on.

## Contents

- [[#1. Why this tool exists]]
- [[#2. Architecture]]
- [[#3. Prerequisite concepts]]
- [[#4. Step-by-step build]]
- [[#5. Testing strategy]]
- [[#6. CI/CD and deployment]]
- [[#7. End-to-end demo]]
- [[#8. Pitfalls and design decisions]]
- [[#9. Roadmap and extensions]]
- [[#10. Skills checklist]]

---

## 1. Why this tool exists

Secrets (API keys, tokens, private keys) get committed constantly. The key problem is that ==git never forgets==: deleting a secret in a later commit does **not** remove it from history. Anyone who can clone the repo can recover it.

```mermaid
flowchart LR
    A["Dev commits key"] --> B["Key pushed to remote"]
    B --> C["Dev notices, deletes key in next commit"]
    C --> D["HEAD is clean"]
    B --> E["Old commit still holds the key"]
    E --> F["Anyone with clone access can read it"]
```

So a useful scanner must look in three places, and catch problems as early as possible:

| Where              | When it runs               | Value                                                        |
| ------------------ | -------------------------- | ------------------------------------------------------------ |
| **Staged changes** | pre-commit hook            | Cheapest fix: the secret never enters history                |
| **Working tree**   | CI on each PR              | Catches what the hook missed                                 |
| **Full history**   | scheduled / first adoption | Finds secrets already leaked, so you know what to **rotate** |

> [!warning] Rotation beats deletion
> If a real secret was ever committed, treat it as compromised and **rotate it**. Rewriting history is secondary.

---

## 2. Architecture

The core design rule: ==three independent stages that only communicate through small data types==.

```mermaid
flowchart LR
    subgraph Sources
        W["worktree: files on disk"]
        S["staged: git diff --cached"]
        H["history: git log -p"]
    end
    subgraph Engine
        R["rules: regex + entropy filter"]
        E["entropy detector (opt-in)"]
        F["filters: placeholder, ignore marker"]
    end
    subgraph Post
        A["allowlist (.secretscan.toml)"]
        B["baseline (fingerprints)"]
    end
    subgraph Output
        T["text"]
        J["JSON"]
        SA["SARIF"]
    end
    W --> |Chunk| R
    S --> |Chunk| R
    H --> |Chunk| R
    R --> F
    E --> F
    F --> |Finding| A --> B
    B --> T
    B --> J
    B --> SA
```

Two types cross the boundaries:

- `Chunk(text, path, line, commit)`: one line of text and where it came from.
- `Finding(rule_id, description, path, line, secret, commit)`: a suspected secret.

Because sources know nothing about rules, and reporters know nothing about git, ==each part can be tested in isolation== and extended without touching the others (e.g. add a new rule without touching git code).

### Project layout

```text
secretscan/
├── pyproject.toml
├── README.md
├── Dockerfile
├── action.yml                  # reusable GitHub Action
├── .pre-commit-hooks.yaml      # for the pre-commit framework
├── .secretscan.toml            # allowlist (dogfooding)
├── .github/workflows/{ci,release}.yml
├── src/secretscan/
│   ├── __init__.py  __main__.py
│   ├── models.py      # Chunk, Finding
│   ├── entropy.py     # Shannon entropy
│   ├── rules.py       # Rule + built-in rules
│   ├── engine.py      # chunks -> findings
│   ├── sources.py     # worktree / staged / history
│   ├── baseline.py    # accepted-findings file
│   ├── config.py      # allowlist
│   ├── reporters.py   # text / json / sarif
│   └── cli.py         # argparse + hook installer
└── tests/
    ├── conftest.py  test_entropy.py  test_engine.py
    └── test_sources.py  test_cli.py
```

---

## 3. Prerequisite concepts

Short primers. Skim what you know, read what you don't.

### 3.1 Regular expressions (the detector's workhorse)

- **Capture groups** `( … )` let a rule match _context_ but report only the secret: `password = "(…)"` reports just the value.
- **Anchors/boundaries** `\b` stop `AKIA…` matching inside a longer word.
- **Compile once**: `re.compile` at import time, not per line.
- **ReDoS**: nested quantifiers like `(a+)+` can take exponential time on crafted input. Our patterns use only bounded character classes, and we also ==skip lines over 4000 chars== to cap the cost.

### 3.2 Generators and streaming

A repo's history can be gigabytes of diffs. Functions that `yield` produce one `Chunk` at a time, so memory use stays flat regardless of repo size. Every source here is a generator.

### 3.3 The unified diff format

`git log -p -U0` prints each change as a **hunk**. `-U0` means zero context lines, so every `+` line is genuinely new.

```diff
commit:67632ec2…                       <- marker we add with --format
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py                          <- header: the NEW path
@@ -1,0 +2,2 @@                        <- hunk: new lines start at line 2
+first                                <- added, line 2
+second                               <- added, line 3
```

The hunk header `@@ -a,b +c,d @@` says new lines start at line **c**; we then count up for each `+` line. That is how we report exact line numbers for history findings.

> [!bug] Classic parser trap
> An added line whose text starts with `++` shows up as `+++…`, which looks like a file header. Only treat `+++ ` as a header ==while in header state==, never inside a hunk.

### 3.4 Shannon entropy (math)

Entropy measures how unpredictable a string's characters are. For a string where character $i$ occurs with relative frequency $p_i$:

$$H = -\sum_{i} p_i \log_2 p_i \quad \text{(bits per character)}$$

Two bounds matter. With $k$ distinct symbols in the alphabet and a string of length $n$:

$$H \le \min\left(\log_2 k,\ \log_2 n\right)$$

| Alphabet   | $k$ | Max $H$           |
| ---------- | --- | ----------------- |
| Hex digits | 16  | $\log_2 16 = 4.0$ |
| Base64     | 64  | $\log_2 64 = 6.0$ |

Consequences you can verify with the code below:

1. ==A hex string (git SHA, MD5) can never exceed 4.0 bits==, so a threshold of 4.3 ignores every hash for free. A 40-char SHA-1 measured 3.97.
2. ==Short strings cap themselves==: a 20-char token can score at most $\log_2 20 \approx 4.32$. A threshold of 4.5 is only reachable when $n \ge 2^{4.5} \approx 22.6$ characters.
3. Real measured values from this project:

| String                  | $n$ | $H$ (bits) |
| ----------------------- | --- | ---------- |
| `aaaaaaaaaaaa`          | 12  | 0.00       |
| `correct-horse-battery` | 21  | 3.27       |
| UUID                    | 36  | 3.39       |
| a file path             | 33  | 3.51       |
| 40-char SHA-1           | 40  | 3.97       |
| AWS key `AKIA…`         | 20  | 4.22       |
| random 31-char token    | 31  | 4.95       |

> [!tip] Takeaway
> Entropy alone is a **noisy** signal (an AWS key and an English path score similarly). That is why we use it as an ==opt-in secondary detector== and rely on specific regex rules as the primary one.

### 3.5 Fingerprints (hashing)

A baseline needs a stable ID for "this exact known finding". We use

$$\text{fingerprint} = \text{SHA-256}(\text{rule}\,\|\,\text{path}\,\|\,\text{secret})[:16\ \text{hex}]$$

Not including the line number means ==the baseline survives code moving around==. 16 hex chars is 64 bits. By the birthday bound, the chance of any collision among $n$ findings is about $n^2 / 2^{65}$; for a million findings that is roughly $2.7 \times 10^{-8}$, which is negligible.

### 3.6 SARIF

**SARIF 2.1.0** is a JSON standard for static-analysis results. Upload it with GitHub's `upload-sarif` action and findings appear in the repo's **Security → Code scanning** tab and as PR annotations. You need: `runs[].tool.driver` (name, rules) and `runs[].results[]` (ruleId, message, location with `startLine`, optional `partialFingerprints`).

### 3.7 Python tooling you will use

`dataclasses`, `pathlib`, `argparse`, `subprocess`, `tomllib` (3.11+), `pytest` fixtures, `hypothesis` (property tests), `ruff`, `mypy --strict`, `pyproject.toml` + `hatchling` packaging.

---

## 4. Step-by-step build

> [!todo] Setup
>
> ```bash
> mkdir secretscan && cd secretscan && git init -b main
> python3 -m venv .venv && source .venv/bin/activate
> mkdir -p src/secretscan tests .github/workflows
> ```
>
> Python ≥ 3.11 is required (for `tomllib`).

### Step 0: Packaging (`pyproject.toml`)

**Concept:** `pyproject.toml` declares metadata, the console script, and dev tools. ==`dependencies = []`==: using only the standard library makes installation instant and removes supply-chain risk, a nice property for a security tool.

```toml
# pyproject.toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "secretscan"
version = "0.1.0"
description = "Find leaked secrets in files, staged changes and git history"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = []                      # zero runtime dependencies on purpose

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-cov", "hypothesis", "ruff", "mypy", "build"]

[project.scripts]
secretscan = "secretscan.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/secretscan"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]

[tool.mypy]
strict = true
files = ["src"]
```

Install in editable mode so edits are live: `pip install -e ".[dev]"`.

### Step 1: Data types (`models.py`)

**Concept:** frozen dataclasses give immutable, hashable value objects. Two details matter:

- `secret` has `repr=False`, so ==a stray `print(finding)` or traceback can never leak the secret==.
- `redacted` keeps 4 leading and 2 trailing characters, enough for a human to recognise the key, not enough to use it.

```python
# src/secretscan/__init__.py
"""secretscan: find leaked secrets in files, staged changes and git history."""

__version__ = "0.1.0"
```

```python
# src/secretscan/models.py
"""Plain data types shared by every other module."""

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
```

### Step 2: Entropy (`entropy.py`)

**Concept:** implement $H = -\sum p_i \log_2 p_i$ literally. `Counter` gives character counts; dividing by $n$ gives $p_i$. `TOKEN_RE` defines candidate tokens: 20+ characters from the base64/URL-safe alphabet.

```python
# src/secretscan/entropy.py
"""Shannon entropy: how random does a string look?"""

from __future__ import annotations

import math
import re
from collections import Counter

# Candidate tokens for the entropy detector: 20+ chars from the base64/url-safe alphabet.
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def shannon_entropy(s: str) -> float:
    """H = -sum(p_i * log2(p_i)) over the characters of s, in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    h = -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
    return max(0.0, h)  # avoids printing -0.0 for constant strings
```

**Test it first** (`tests/test_entropy.py`). Note the property test: for _any_ string, $0 \le H \le \log_2(\text{distinct symbols})$.

```python
# tests/test_entropy.py
import math

from hypothesis import given
from hypothesis import strategies as st

from secretscan.entropy import shannon_entropy


def test_empty_and_constant_strings_have_zero_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_two_equally_likely_symbols_is_one_bit():
    assert shannon_entropy("abab") == 1.0


def test_uniform_hex_alphabet_is_four_bits():
    assert math.isclose(shannon_entropy("0123456789abcdef"), 4.0)


@given(st.text(min_size=1, max_size=200))
def test_entropy_is_bounded_by_log2_of_distinct_symbols(s):
    h = shannon_entropy(s)
    assert -1e-9 <= h <= math.log2(len(set(s))) + 1e-9 if len(set(s)) > 1 else h == 0
```

> [!success] Checkpoint
> `pytest tests/test_entropy.py` passes. Try `python -c "from secretscan.entropy import shannon_entropy as H; print(H('0123456789abcdef'))"` → `4.0`.

### Step 3: Rules (`rules.py`)

**Concept:** a `Rule` is a regex + which capture group is the secret + an optional `min_entropy` filter. Specific provider rules (AWS, GitHub, Slack) have **low false-positive rates** because their formats are rigid. The generic `password = "…"` rule is broad, so it requires entropy ≥ 3.0 to drop things like `"aaaaaaaa"` or `"changeme"`.

Where do formats come from? Provider docs: AWS access key IDs start `AKIA` (long-term) or `ASIA` (temporary) plus 16 uppercase alphanumerics, giving a key-ID space of $32^{16} = 2^{80}$. GitHub tokens use prefixes `ghp_ gho_ ghu_ ghs_ ghr_`.

```python
# src/secretscan/rules.py
"""Detection rules: a regex plus optional filters."""

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
```

> [!tip] Adding a rule
> Append a `Rule(...)`. Put **specific** rules before **generic** ones: the engine reports each secret once, from the first rule that matches it.

### Step 4: The engine (`engine.py`)

**Concept:** for each chunk, apply every rule, then (optionally) the entropy detector, with these filters:

1. `# secretscan:ignore` on the line suppresses it (inline allowlist).
2. Placeholder secrets (`example`, `changeme`, `your_`, …) are skipped; this is why AWS's documented example key doesn't alert.
3. A `seen` set de-duplicates, so `api_key = "AKIA…"` yields ==one finding (AWS), not two==.
4. Lines over `MAX_LINE` are skipped, bounding regex cost.

```mermaid
flowchart TD
    C["Chunk"] --> L{"line too long or has ignore marker?"}
    L -- yes --> X["skip"]
    L -- no --> RL["for each rule: finditer"]
    RL --> P{"placeholder or already seen?"}
    P -- yes --> RL
    P -- no --> EN{"rule has min_entropy and H below it?"}
    EN -- yes --> RL
    EN -- no --> Y["yield Finding"]
    RL --> ED{"entropy threshold set?"}
    ED -- yes --> TK["for each 20+ char token: H >= threshold?"]
    TK --> Y
```

```python
# src/secretscan/engine.py
"""Turn chunks of text into findings."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .entropy import TOKEN_RE, shannon_entropy
from .models import Chunk, Finding
from .rules import BUILTIN_RULES, Rule

IGNORE_MARKER = "secretscan:ignore"
MAX_LINE = 4000  # skip absurdly long lines (minified JS): bounds regex cost
PLACEHOLDERS = ("example", "changeme", "your_", "<", "xxxx", "placeholder", "dummy")


def looks_like_placeholder(secret: str) -> bool:
    low = secret.lower()
    return any(p in low for p in PLACEHOLDERS)


def scan_chunk(
    chunk: Chunk,
    rules: Iterable[Rule] = BUILTIN_RULES,
    entropy_threshold: float | None = None,
) -> Iterator[Finding]:
    text = chunk.text
    if len(text) > MAX_LINE or IGNORE_MARKER in text:
        return

    seen: set[str] = set()

    def make(rule_id: str, desc: str, secret: str) -> Finding:
        return Finding(rule_id, desc, chunk.path, chunk.line, secret, chunk.commit)

    for rule in rules:
        for m in rule.pattern.finditer(text):
            secret = m.group(rule.group)
            if secret in seen or looks_like_placeholder(secret):
                continue
            if rule.min_entropy is not None and shannon_entropy(secret) < rule.min_entropy:
                continue
            seen.add(secret)
            yield make(rule.id, rule.description, secret)

    if entropy_threshold is not None:
        for m in TOKEN_RE.finditer(text):
            token = m.group(0)
            if token in seen or looks_like_placeholder(token):
                continue
            if shannon_entropy(token) >= entropy_threshold:
                seen.add(token)
                yield make("high-entropy", "High-entropy string", token)


def scan_chunks(
    chunks: Iterable[Chunk],
    rules: Iterable[Rule] = BUILTIN_RULES,
    entropy_threshold: float | None = None,
) -> Iterator[Finding]:
    rules = tuple(rules)  # allow any iterable, iterate many times
    for chunk in chunks:
        yield from scan_chunk(chunk, rules, entropy_threshold)
```

**Tests** (`tests/conftest.py` + `tests/test_engine.py`). Notice fake secrets are ==assembled at runtime== (`"AKIA" + "QWERTY…"`) so the repo's own source doesn't contain a literal key that scanners (including this one) would flag.

```python
# tests/conftest.py
import os
import subprocess
from pathlib import Path

import pytest

# Fake secrets are assembled at runtime so this repo never trips its own scanner.
AWS_KEY = "AKIA" + "QWERTY1234567890"
GH_TOKEN = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
}  # fmt: skip


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=GIT_ENV
    )
    return out.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


@pytest.fixture
def aws_key() -> str:
    return AWS_KEY


@pytest.fixture
def gh_token() -> str:
    return GH_TOKEN
```

```python
# tests/test_engine.py
from secretscan.engine import scan_chunk
from secretscan.models import Chunk


def run(text, **kw):
    return list(scan_chunk(Chunk(text, "f.py", 3), **kw))


def test_detects_aws_key_with_location(aws_key):
    [f] = run(f"key = {aws_key}")
    assert (f.rule_id, f.path, f.line, f.secret) == ("aws-access-key-id", "f.py", 3, aws_key)


def test_detects_github_token(gh_token):
    assert [f.rule_id for f in run(f"export GH={gh_token}")] == ["github-token"]


def test_detects_private_key_header():
    assert [f.rule_id for f in run("-----BEGIN RSA PRIVATE KEY-----")] == ["private-key"]


def test_clean_line_has_no_findings():
    assert run("x = compute(1, 2)  # nothing to see") == []


def test_inline_ignore_marker_suppresses(aws_key):
    assert run(f"key = {aws_key}  # secretscan:ignore") == []


def test_placeholder_values_are_skipped():
    assert run('api_key = "your_api_key_here"') == []
    assert run("AKIAIOSFODNN7EXAMPLE") == []


def test_generic_rule_needs_enough_entropy():
    assert [f.rule_id for f in run('password = "correct-horse-battery"')] == ["generic-credential"]
    assert run('password = "aaaaaaaaaaaa"') == []  # entropy 0 -> boring, ignore


def test_specific_rule_wins_over_generic(aws_key):
    ids = [f.rule_id for f in run(f'api_key = "{aws_key}"')]
    assert ids == ["aws-access-key-id"]  # reported once, not twice


def test_entropy_detector_is_opt_in():
    blob = "Zk9xQ2v8Lw3Rt7Yb1Nc5Hd4Jm6Pa0Se"
    assert run(f"data = {blob}") == []
    assert [f.rule_id for f in run(f"data = {blob}", entropy_threshold=4.0)] == ["high-entropy"]


def test_git_sha_is_not_flagged_as_high_entropy():
    sha = "a3f5c9e1b27d4086f1e2c3d4b5a69788c9d0e1f2"  # hex alphabet caps entropy at 4 bits
    assert run(f"commit {sha}", entropy_threshold=4.3) == []


def test_finding_repr_never_contains_the_secret(aws_key):
    [f] = run(aws_key)
    assert aws_key not in repr(f)
    assert aws_key not in f.redacted
```

> [!success] Checkpoint
> `pytest tests/test_engine.py` passes. You now have a working detector for plain strings, which is ==the heart of the project==. Everything else is plumbing.

### Step 5: Sources (`sources.py`)

**Concept:** sources turn the outside world into `Chunk`s. Three of them share one diff parser.

**Working tree.** `os.walk` with in-place pruning of `dirnames` (skips `.git`, `node_modules`, venvs). Skip symlinks (avoid loops and escaping the repo), files over 1 MB, and binary files (a NUL byte in the first 8 KiB is the classic heuristic). Decode with `errors="replace"` so odd encodings never crash the scan.

**Git commands.** We shell out to `git` using `subprocess.Popen` and stream stdout. Stderr goes to a temp file, not a pipe: ==if both are pipes and you only read stdout, a chatty stderr fills its buffer and the process deadlocks==.

**The diff parser** is a tiny state machine:

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Header: "diff --git" line
    Header --> Header: "+++ b/path" sets current path
    Header --> Hunk: "@@ -a,b +c,d @@" sets line = c
    Hunk --> Hunk: "+" line, emit Chunk and line += 1
    Hunk --> Header: next "diff --git" line
    Hunk --> Idle: "commit:sha" marker
    Idle --> Idle: "commit:sha" marker
```

```python
# src/secretscan/sources.py
"""Where text comes from: the working tree, staged changes, or git history.

Every source yields `Chunk`s and knows nothing about rules.
"""

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


# ---------------------------------------------------------------- working tree
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


# ----------------------------------------------------------------- git helpers
def _git_lines(repo: Path, *args: str) -> Iterator[str]:
    """Stream stdout lines of a git command; raise GitError on failure."""
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
    """Yield every *added* line of a unified diff (-U0) with its new line number.

    Understands an optional `commit:<sha>` marker line before each commit's diff.
    """
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


# ------------------------------------------------------------ staged / history
def iter_staged(repo: Path) -> Iterator[Chunk]:
    yield from parse_diff(_git_lines(repo, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff"))


def iter_history(repo: Path, revs: tuple[str, ...] = ("--all",)) -> Iterator[Chunk]:
    yield from parse_diff(
        _git_lines(
            repo, "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=commit:%H", *revs
        )
    )
```

**Tests** (`tests/test_sources.py`). The most valuable one builds a real temporary git repo, commits a line, deletes it, and asserts history still contains it, which is ==the whole reason the history mode exists==.

```python
# tests/test_sources.py
from conftest import git

from secretscan.sources import iter_history, iter_staged, iter_worktree, parse_diff

DIFF = """\
commit:abc123
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -1,0 +2,2 @@
+first
+++not a header
@@ -9 +12 @@
-old
+second
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""


def test_parse_diff_tracks_paths_lines_and_commit():
    got = [(c.path, c.line, c.text, c.commit) for c in parse_diff(DIFF.splitlines())]
    assert got == [
        ("app.py", 2, "first", "abc123"),
        ("app.py", 3, "++not a header", "abc123"),  # '+++' inside a hunk is content
        ("app.py", 12, "second", "abc123"),
    ]


def test_worktree_skips_binary_git_and_big_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello\nworld\n")
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01secret")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("ignored")
    (tmp_path / "big.txt").write_text("x" * 200)
    chunks = list(iter_worktree(tmp_path, max_bytes=100))
    assert [(c.path, c.line, c.text) for c in chunks] == [("a.txt", 1, "hello"), ("a.txt", 2, "world")]


def test_staged_only_sees_staged_additions(repo):
    (repo / "a.txt").write_text("one\ntwo\n")
    git(repo, "add", "a.txt")
    (repo / "b.txt").write_text("unstaged\n")
    assert [(c.path, c.line, c.text) for c in iter_staged(repo)] == [
        ("a.txt", 1, "one"), ("a.txt", 2, "two"),
    ]  # fmt: skip


def test_history_finds_lines_that_were_later_deleted(repo):
    f = repo / "cfg.txt"
    f.write_text("token_line\n")
    git(repo, "add", "."), git(repo, "commit", "-qm", "add")
    f.write_text("clean\n")
    git(repo, "commit", "-qam", "remove")
    texts = [c.text for c in iter_history(repo)]
    assert "token_line" in texts  # gone from HEAD, still in history
    assert "clean" in texts
```

> [!success] Checkpoint
> `pytest tests/test_sources.py` passes. Try it by hand: `python -c "from pathlib import Path; from secretscan.sources import iter_history; print(sum(1 for _ in iter_history(Path('.'))))"`.

### Step 6: Baselines (`baseline.py`)

**Concept:** adopting a scanner on a 5-year-old repo yields hundreds of old findings; if they all fail the build, nobody will adopt it. A **baseline** records today's findings (as fingerprints, see §3.5) so ==only new ones fail CI==.

Workflow: `secretscan scan . --history --write-baseline .secretscan-baseline.json` once, commit the file, then `secretscan scan . --baseline .secretscan-baseline.json` in CI.

```python
# src/secretscan/baseline.py
"""Baselines: accept today's findings so only *new* ones fail the build."""

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
```

### Step 7: Allowlist config (`config.py`)

**Concept:** path globs (for fixtures and docs) and secret regexes (for known-fake values), read from `.secretscan.toml` using the stdlib `tomllib`. The project uses this on itself:

```toml
# .secretscan.toml
# Test fixtures deliberately contain fake credentials.
[allowlist]
paths = ["tests/*"]
```

```python
# src/secretscan/config.py
"""Optional `.secretscan.toml` allowlist.

    [allowlist]
    paths   = ["tests/fixtures/*", "docs/*"]   # glob patterns on the finding's path
    regexes = ["^test_"]                       # regexes matched against the secret
"""

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
```

### Step 8: Reporters (`reporters.py`)

**Concept:** pure functions `list[Finding] -> str`. Hard rules enforced here and tested: ==no reporter ever emits the full secret==. SARIF carries the fingerprint in `partialFingerprints` so GitHub can track the same alert across commits.

```python
# src/secretscan/reporters.py
"""Output formats. None of them ever emit the full secret."""

from __future__ import annotations

import json
from collections.abc import Sequence

from . import __version__
from .models import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def to_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return "No secrets found.\n"
    lines = []
    for f in findings:
        where = f"{f.path}:{f.line}"
        commit = f"  (commit {f.commit[:8]})" if f.commit else ""
        lines.append(f"{where}  [{f.rule_id}] {f.description}  {f.redacted}{commit}")
    lines.append(f"\n{len(findings)} potential secret(s) found.")
    return "\n".join(lines) + "\n"


def to_json(findings: Sequence[Finding]) -> str:
    items = [
        {
            "rule": f.rule_id,
            "path": f.path,
            "line": f.line,
            "commit": f.commit,
            "secret": f.redacted,
            "fingerprint": f.fingerprint,
        }
        for f in findings
    ]
    return json.dumps({"findings": items}, indent=2) + "\n"


def to_sarif(findings: Sequence[Finding]) -> str:
    rules = {f.rule_id: f.description for f in findings}
    results = [
        {
            "ruleId": f.rule_id,
            "level": "error",
            "message": {"text": f"{f.description} ({f.redacted})"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line},
                    }
                }
            ],
            "partialFingerprints": {"secretscan/v1": f.fingerprint},
        }
        for f in findings
    ]
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretscan",
                        "version": __version__,
                        "rules": [
                            {"id": rid, "shortDescription": {"text": d}}
                            for rid, d in sorted(rules.items())
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif}
```

### Step 9: CLI and hook (`cli.py`, `__main__.py`)

**Concept:** `argparse` with two subcommands. The exit code is the contract with CI and git hooks:

| Exit code | Meaning                                                   |
| --------- | --------------------------------------------------------- |
| `0`       | clean                                                     |
| `1`       | findings reported                                         |
| `2`       | operational error (bad path, not a git repo, git failure) |

Distinguishing `1` from `2` matters: a broken scan must not look like a clean one, and it must not look like a finding either.

`install-hook` asks git where hooks live (`git rev-parse --git-path hooks/pre-commit`, which respects `core.hooksPath` and worktrees), writes a 3-line shell script, and `chmod +x`.

```mermaid
sequenceDiagram
    participant Dev
    participant Git
    participant Hook as pre-commit hook
    participant SS as secretscan --staged
    Dev->>Git: git commit
    Git->>Hook: run .git/hooks/pre-commit
    Hook->>SS: exec secretscan scan --staged
    SS->>Git: git diff --cached -U0
    Git-->>SS: added lines
    alt secret found
        SS-->>Hook: exit 1
        Hook-->>Git: non-zero
        Git-->>Dev: commit aborted
    else clean
        SS-->>Hook: exit 0
        Git-->>Dev: commit created
    end
```

```python
# src/secretscan/cli.py
"""Command-line interface. Exit codes: 0 clean, 1 findings, 2 error."""

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
                      help="scan every commit (optionally limited to revisions, e.g. main~20..HEAD)")  # fmt: skip
    s.add_argument("--entropy", type=float, metavar="BITS", default=None,
                   help="also flag random-looking tokens at or above this entropy (try 4.5)")  # fmt: skip
    s.add_argument("--baseline", type=Path, help="ignore findings recorded in this baseline")
    s.add_argument("--write-baseline", type=Path, metavar="FILE",
                   help="record current findings as the baseline and exit 0")  # fmt: skip
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
    )  # fmt: skip
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
```

```python
# src/secretscan/__main__.py
import sys

from .cli import main

sys.exit(main())
```

**Tests** (`tests/test_cli.py`) exercise the real `main()` against temp dirs and repos: exit codes, redaction in output, history vs worktree, the baseline round trip (including _line shifts_), allowlist, SARIF shape, error paths and hook installation.

```python
# tests/test_cli.py
import json
import os
import stat

from conftest import git

from secretscan.cli import main


def test_clean_tree_exits_zero(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    assert main(["scan", str(tmp_path)]) == 0
    assert "No secrets found" in capsys.readouterr().out


def test_finding_exits_one_and_redacts(tmp_path, capsys, aws_key):
    (tmp_path / "cfg.py").write_text(f"KEY = '{aws_key}'\n")
    assert main(["scan", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "cfg.py:1" in out and "aws-access-key-id" in out
    assert aws_key not in out


def test_history_scan_catches_removed_secret(repo, capsys, aws_key):
    f = repo / "cfg.py"
    f.write_text(f"KEY = '{aws_key}'\n")
    git(repo, "add", "."), git(repo, "commit", "-qm", "oops")
    f.write_text("KEY = None\n")
    git(repo, "commit", "-qam", "fix")
    assert main(["scan", str(repo)]) == 0  # working tree is clean...
    assert main(["scan", str(repo), "--history"]) == 1  # ...history is not
    assert "commit " in capsys.readouterr().out


def test_baseline_roundtrip_hides_old_but_not_new(tmp_path, aws_key, gh_token):
    (tmp_path / "a.py").write_text(f"K='{aws_key}'\n")
    base = tmp_path.parent / (tmp_path.name + "-base.json")
    assert main(["scan", str(tmp_path), "--write-baseline", str(base)]) == 0
    assert main(["scan", str(tmp_path), "--baseline", str(base)]) == 0
    (tmp_path / "a.py").write_text(f"# moved down\nK='{aws_key}'\n")  # line shift: still baselined
    assert main(["scan", str(tmp_path), "--baseline", str(base)]) == 0
    (tmp_path / "b.py").write_text(f"T='{gh_token}'\n")
    assert main(["scan", str(tmp_path), "--baseline", str(base)]) == 1


def test_allowlist_config(tmp_path, aws_key):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "k.py").write_text(f"K='{aws_key}'\n")
    (tmp_path / ".secretscan.toml").write_text('[allowlist]\npaths = ["fixtures/*"]\n')
    assert main(["scan", str(tmp_path)]) == 0


def test_sarif_output_shape_and_no_raw_secret(tmp_path, aws_key):
    (tmp_path / "a.py").write_text(f"K='{aws_key}'\n")
    out = tmp_path.parent / (tmp_path.name + ".sarif")
    assert main(["scan", str(tmp_path), "--format", "sarif", "--output", str(out)]) == 1
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    [result] = doc["runs"][0]["results"]
    assert result["ruleId"] == "aws-access-key-id"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert aws_key not in out.read_text()


def test_bad_baseline_path_is_an_error(tmp_path):
    assert main(["scan", str(tmp_path), "--baseline", str(tmp_path / "nope.json")]) == 2


def test_not_a_git_repo_is_an_error(tmp_path):
    assert main(["scan", str(tmp_path), "--staged"]) == 2


def test_install_hook_and_precommit_blocks_secret(repo, aws_key):
    assert main(["install-hook", str(repo)]) == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.stat().st_mode & stat.S_IXUSR
    assert main(["install-hook", str(repo)]) == 2  # refuses to overwrite
    assert main(["install-hook", str(repo), "--force"]) == 0
    (repo / "a.py").write_text(f"K='{aws_key}'\n")
    git(repo, "add", "a.py")
    prev = os.getcwd()
    os.chdir(repo)  # hook runs `secretscan scan --staged` in the repo
    try:
        assert main(["scan", "--staged"]) == 1
    finally:
        os.chdir(prev)
```

> [!success] Checkpoint
> `pytest` is fully green, and `secretscan scan .` works from your shell.

---

## 5. Testing strategy

| Layer                     | What                                                        | Why                                         |
| ------------------------- | ----------------------------------------------------------- | ------------------------------------------- |
| **Unit**                  | `shannon_entropy`, each rule, engine filters, `parse_diff`  | Fast, pinpoint failures                     |
| **Property** (Hypothesis) | entropy bounds $0 \le H \le \log_2 k$ for arbitrary strings | Finds edge cases you wouldn't write by hand |
| **Integration**           | real temp git repos: staged, history, hook                  | Git behaviour is the riskiest assumption    |
| **CLI/contract**          | exit codes, output redaction, SARIF shape                   | These are the public API                    |
| **Dogfood** (CI)          | scan this repo + its history                                | The tool must pass its own standard         |

Run locally:

```bash
pip install -e ".[dev]"
pytest --cov=secretscan --cov-report=term-missing
ruff check . && ruff format --check . && mypy
```

> [!note] Measuring quality, not just coverage
> Coverage says the lines ran; it doesn't say detection is _good_. For a real release, build a small labelled corpus (true secrets + tricky non-secrets such as hashes, UUIDs, base64 test data) and report **precision** $= \frac{TP}{TP+FP}$ and **recall** $= \frac{TP}{TP+FN}$ per rule. Put the numbers in the README.

---

## 6. CI/CD and deployment

```mermaid
flowchart LR
    PR["push / PR"] --> LINT["lint: ruff + mypy"]
    LINT --> TEST["test matrix: 3 OS x 3 Python"]
    LINT --> DOG["dogfood: scan own history, upload SARIF"]
    TEST --> BUILD["build wheel + sdist"]
    DOG --> BUILD
    TAG["git tag v*"] --> PYPI["publish to PyPI (OIDC)"]
    TAG --> DOCKER["build + push image to GHCR"]
```

### 6.1 CI (`.github/workflows/ci.yml`)

Key decisions:

- **`needs: lint`**: don't burn 9 matrix jobs on code that fails formatting.
- **Matrix** across Linux/macOS/Windows and Python 3.11-3.13 (subprocess and path handling differ by OS, and this is where the bugs hide).
- **`--cov-fail-under=90`** turns coverage into a gate.
- **`fetch-depth: 0`** in dogfood: shallow clones have no history to scan.
- **`permissions:`** least privilege; only the SARIF job gets `security-events: write`.

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          cache: pip
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: mypy

  test:
    needs: lint
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python: ["3.11", "3.12", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
          cache: pip
      - run: pip install -e ".[dev]"
      - run: pytest --cov=secretscan --cov-report=term-missing --cov-report=xml --cov-fail-under=90
      - uses: actions/upload-artifact@v4
        if: matrix.os == 'ubuntu-latest' && matrix.python == '3.13'
        with:
          name: coverage
          path: coverage.xml

  dogfood:
    # The scanner must pass its own scan, including full history.
    needs: lint
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # history scan needs every commit
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install .
      - run: secretscan scan . --history --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

  build:
    needs: [test, dogfood]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install build && python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

> [!warning] Action versions
> Pin to current major versions of `actions/checkout`, `setup-python`, `upload-artifact`, `github/codeql-action`, `docker/*` and `pypa/gh-action-pypi-publish` when you create the repo. Majors move, so check each action's releases page.

### 6.2 Release (`.github/workflows/release.yml`)

Pushing a tag like `v0.1.0` publishes to PyPI and GHCR. ==PyPI **trusted publishing** (OIDC) means no API token is stored in GitHub secrets at all==. One-time setup: on pypi.org add a "pending publisher" for your repo, workflow `release.yml`, environment `pypi`.

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ["v*"]

jobs:
  pypi:
    runs-on: ubuntu-latest
    environment: pypi # create this environment in repo settings
    permissions:
      id-token: write # OIDC "trusted publishing": no API token stored anywhere
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install build && python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1

  docker:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.ref_name }}
            ghcr.io/${{ github.repository }}:latest
```

Release steps:

```bash
# bump version in pyproject.toml and src/secretscan/__init__.py, commit, then:
git tag v0.1.0 && git push origin v0.1.0
```

### 6.3 Docker (`Dockerfile`)

Multi-stage: build the wheel in one stage, install it into a clean slim runtime. Runs as a ==non-root user==. `git` is installed because `--staged` and `--history` shell out to it.

```dockerfile
# Dockerfile
# --- build stage: make a wheel
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

# --- runtime stage: small image, non-root, git available for --history/--staged
FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home scanner
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER scanner
WORKDIR /repo
# Mounted repos are owned by another uid; tell git that's fine.
RUN git config --global --add safe.directory /repo
ENTRYPOINT ["secretscan"]
CMD ["scan", "."]
```

```bash
docker build -t secretscan .
docker run --rm -v "$PWD:/repo" secretscan scan . --history
```

### 6.4 Reusable GitHub Action (`action.yml`)

Lets anyone write `uses: your-user/secretscan@v0.1.0`.

```yaml
# action.yml
name: secretscan
description: Scan a repository (including git history) for leaked secrets
inputs:
  path:
    description: Path to scan
    default: "."
  history:
    description: Also scan full git history (needs fetch-depth 0)
    default: "true"
  args:
    description: Extra arguments, e.g. "--baseline .secretscan-baseline.json --entropy 4.5"
    default: ""
runs:
  using: composite
  steps:
    - uses: actions/setup-python@v5
      with:
        python-version: "3.13"
    - run: pip install secretscan
      shell: bash
    - shell: bash
      run: |
        flags=""
        if [ "${{ inputs.history }}" = "true" ]; then flags="--history"; fi
        secretscan scan "${{ inputs.path }}" $flags ${{ inputs.args }}
```

Consumer example:

```yaml
name: secrets
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: your-user/secretscan@v0.1.0
        with:
          args: --baseline .secretscan-baseline.json
```

### 6.5 pre-commit framework (`.pre-commit-hooks.yaml`)

Users of [pre-commit](https://pre-commit.com) can then reference your repo:

```yaml
# .pre-commit-hooks.yaml
- id: secretscan
  name: secretscan
  description: Block commits that contain secrets
  entry: secretscan scan --staged
  language: python
  pass_filenames: false
  always_run: true
```

```yaml
# their .pre-commit-config.yaml
repos:
  - repo: https://github.com/your-user/secretscan
    rev: v0.1.0
    hooks:
      - id: secretscan
```

---

## 7. End-to-end demo

This is a real transcript from the finished tool: install the hook, try to commit a key, bypass the hook, "fix" it, then show that the history scan still catches it.

```console
$ secretscan install-hook .
Installed .git/hooks/pre-commit

$ echo "KEY = 'AKIAQWERTY1234567890'" > app.py && git add app.py
$ git commit -m "add key"
app.py:1  [aws-access-key-id] AWS access key ID  AKIA…90

1 potential secret(s) found.
$ echo $?
1                                        # commit was blocked

$ git commit --no-verify -m "oops"       # developer bypasses the hook
$ echo "KEY = None" > app.py && git commit -am fix

$ secretscan scan .                      # working tree looks clean
No secrets found.

$ secretscan scan . --history            # but history remembers
app.py:1  [aws-access-key-id] AWS access key ID  AKIA…90  (commit 67632ec2)

1 potential secret(s) found.
```

The entropy detector on a SHA-1 and a random token (threshold 4.3):

```console
$ printf 'sha = "a3f5c9e1b27d4086f1e2c3d4b5a69788c9d0e1f2"\nblob = Zk9xQ2v8Lw3Rt7Yb1Nc5Hd4Jm6Pa0Se\n' > c.txt
$ secretscan scan . --entropy 4.3
c.txt:2  [high-entropy] High-entropy string  Zk9x…Se
```

The SHA-1 (3.97 bits, hex alphabet) is ignored; the random token (4.95 bits) is flagged. That is the math from §3.4 working in practice.

> [!example] Verification notes
> All 28 tests passed and the demo above was run on the finished code. The sandbox that built this couldn't reach PyPI, so the tests were run with a small stand-in runner rather than real `pytest`/`hypothesis` (the Hypothesis test ran as 300 random strings). The first thing to do on your machine is `pip install -e ".[dev]" && pytest`.

---

## 8. Pitfalls and design decisions

> [!danger] Never leak what you find
> Redact in **all** outputs, logs and exceptions. `repr=False` on the secret field, a `redacted` property, and tests asserting the raw value never appears in output (text, JSON, SARIF).

| Pitfall                 | What goes wrong                                                  | What we did                                                                     |
| ----------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **False positives**     | Hashes, UUIDs, base64 test data, docs examples drown real alerts | Specific rules first; entropy opt-in; placeholder filter; allowlists; baselines |
| **False negatives**     | Secrets with unusual formats slip by                             | Entropy mode; easy rule additions; measure recall on a corpus                   |
| **Huge repos**          | Slow history scans, memory blowups                               | Generators end to end; skip binaries/large files/long lines                     |
| **Shallow clones**      | CI checkout has no history                                       | `fetch-depth: 0`, documented                                                    |
| **Diff parsing**        | `+++` inside content, deleted files, renames                     | State machine; tests for each case                                              |
| **Subprocess deadlock** | Unread stderr pipe fills                                         | stderr to a temp file                                                           |
| **Baseline drift**      | Line-based IDs break when code moves                             | Fingerprint excludes line number                                                |
| **Hook bypass**         | `git commit --no-verify`                                         | Hook is convenience, **CI is the enforcement**                                  |
| **Windows**             | Path separators, `chmod`                                         | `as_posix()` for reported paths; CI matrix includes Windows                     |

### Design decisions worth explaining in an interview

1. **Why zero dependencies?** Security tools should have a tiny attack surface and install anywhere.
2. **Why `subprocess` git rather than a library?** No dependency, matches exactly what users see, easy to stream; trade-off is you parse text output.
3. **Why separate Sources/Engine/Reporters?** Testability and extension. A new source (e.g. scan a Docker image layer) needs zero engine changes.
4. **Why is entropy opt-in?** Precision. Users who want recall can enable it and tune the threshold.
5. **Why exit code 2 for errors?** CI must distinguish "scan failed to run" from "secrets found".

---

## 9. Roadmap and extensions

Ordered by learning value:

1. **Validate before alerting**: for AWS keys, check the secret-key pair structure; for GitHub tokens, verify the checksum embedded in newer token formats. Fewer false positives.
2. **Performance**: combine all rule patterns with a cheap pre-filter (e.g. `str.__contains__` on prefixes like `AKIA`, `ghp_`) before running regexes; benchmark with `pytest-benchmark`. Then parallelise history with `concurrent.futures` per commit range.
3. **More rules**: Stripe, Google API keys, Twilio, npm tokens, connection strings with embedded passwords (`postgres://user:pass@host`).
4. **Config-defined custom rules** in `.secretscan.toml` (id, regex, optional entropy).
5. **Decode-and-rescan**: base64 blobs that wrap secrets.
6. **`.gitignore`-aware walking**, and `--exclude` globs on the CLI.
7. **Report who/when**: add author and date from `git log --format` to history findings.
8. **Benchmark README**: scan a large public repo's history; report time and findings vs. an established scanner; publish precision/recall from your labelled corpus.
9. **Type-checked public API** with a `py.typed` marker so others can `import secretscan` as a library.

---

## 10. Skills checklist

Tick these off as you build; each one is something you can now talk about with evidence.

- [ ] Wrote a streaming (generator-based) pipeline
- [ ] Parsed a real text format (unified diff) with a state machine
- [ ] Designed with clear module boundaries (Sources → Engine → Reporters)
- [ ] Used information theory ($H$) with an understanding of its limits
- [ ] Safe handling of sensitive data (redaction by default)
- [ ] Wrote unit, property, integration and contract tests
- [ ] Defined a CLI contract with meaningful exit codes
- [ ] Built a git hook and a pre-commit-framework hook
- [ ] Produced SARIF and integrated with GitHub code scanning
- [ ] CI matrix across OS/Python versions with lint, type-check, coverage gate
- [ ] Release automation with keyless PyPI publishing and a container image
- [ ] Shipped a reusable GitHub Action

> [!quote] Final thought
> The impressive part of this project isn't the regexes. It's that ==the tool is safe by default, honest about its error rate, measured, tested, and shipped end to end==.
