# Contributing

Thanks for helping. Bug reports, new rules and fixes are all welcome.

## Setup

Requires Python 3.11+ and `git`.

```bash
git clone https://github.com/harshith-ashok/secretscan && cd secretscan
pip install -e ".[dev]"          # or: uv sync --extra dev
```

## Before you push

CI runs exactly this, so a green local run means a green CI:

```bash
ruff check . && ruff format --check . && mypy
pytest --cov=secretscan --cov-report=term-missing   # CI requires >= 90% coverage
secretscan scan . --history                         # the scanner must pass its own scan
```

Run `ruff format .` first; formatting is the most common failure. `secretscan install-hook .` scans each commit for secrets.

## Workflow

1. Branch from `main`: `feat/...`, `fix/...` or `chore/...`.
2. Make small commits, one change each, with the tests that cover it. Messages follow `(type): summary`, with type `feat`, `fix`, `test` or `chore`.
3. Open a pull request. CI runs lint, the Linux/macOS/Windows by Python 3.11-3.13 matrix, and the dogfood scan.
4. Never commit a real secret, even in a test. Tests build fakes at runtime, e.g. `"AKIA" + "QWERTY1234567890"`.

## Adding a rule

1. Add a `Rule(...)` to `BUILTIN_RULES` in [rules.py](src/secretscan/rules.py). Put specific rules before general ones: each secret is reported once, by the first rule that matches.
2. Set `confidence` (`high` for a rigid vendor prefix, `medium` for looser syntax, `low` for guesses) and an `advice` string saying how to revoke or fix it.
3. Use `min_entropy` or a `validator` to keep out words, hashes and placeholders.
4. Add a positive case and near-miss negatives to [tests/test_rules.py](tests/test_rules.py), with the fake token built at runtime.
5. Run the [real-world suite](#real-world-tests) to check the rule adds no noise, and add a line to `CHANGELOG.md`.

## Tests

| Layer                     | What                                                       | Where                          |
| ------------------------- | ---------------------------------------------------------- | ------------------------------ |
| **Unit**                  | rules, engine filters, diff parser, reporters              | `tests/`                       |
| **Property** (Hypothesis) | entropy stays between 0 and log2 of the distinct symbols   | `tests/test_entropy.py`        |
| **Integration**           | real temporary git repos: staged, history, the hook        | `tests/test_sources.py`, `test_cli.py` |
| **Contract**              | exit codes, redaction, SARIF shape                         | `tests/test_cli.py`, `test_reporters.py` |
| **Real-world**            | clone real repos and scan their full history               | `realworld/`                   |
| **Dogfood** (CI)          | scan this repo and its history                             | `ci.yml`                       |

Each behaviour maps to a test:

| Behaviour                                                              | Test                                                                                           |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Every rule detects its format; near misses stay quiet                  | `test_rules.py`                                                                                |
| The generic rule ignores hashes, code, key names and plain words       | `test_generic_rule_ignores_hashes_code_and_plain_words`                                        |
| A specific rule wins over a general one (one finding, not two)         | `test_specific_rule_wins_over_generic`, `test_specific_rule_beats_the_env_rule`                |
| Reports the right rule, path and line                                  | `test_detects_aws_key_with_location`                                                           |
| `# secretscan:ignore` suppresses a line                                | `test_inline_ignore_marker_suppresses`                                                         |
| Placeholders (`example`, `your_`, ...) are skipped                     | `test_placeholder_values_are_skipped`                                                          |
| Entropy detector is opt-in; git SHAs never trip it                     | `test_entropy_detector_is_opt_in`, `test_git_sha_is_not_flagged_as_high_entropy`               |
| Entropy is bounded for any string                                      | `test_entropy.py` (Hypothesis property test)                                                   |
| Confidence, masked match and suggestion on every finding               | `test_finding_carries_confidence_match_and_suggestion`, `test_rule_confidence_levels`, `test_reporters.py` |
| Confidence drops one level in test and docs paths                      | `test_confidence_drops_one_level_in_tests_and_docs`                                            |
| `--min-confidence` filters findings and the exit code                  | `test_min_confidence_filters_and_sets_exit_code`                                               |
| The match line masks every secret on it, so one never leaks another    | `test_context_masks_every_secret_on_the_line`, `test_long_lines_are_trimmed_around_the_match`  |
| The raw secret never appears in `repr`, text or SARIF output           | `test_finding_repr_never_contains_the_secret`, `test_sarif_output_shape_and_no_raw_secret`     |
| Diff parser tracks path, line and commit; `+++` in content is data     | `test_parse_diff_tracks_paths_lines_and_commit`                                                |
| Worktree scan skips binary, `.git` and oversized files                 | `test_worktree_skips_binary_git_and_big_files`                                                 |
| Staged scan sees only staged additions                                 | `test_staged_only_sees_staged_additions`                                                       |
| History finds a line that was later deleted                            | `test_history_finds_lines_that_were_later_deleted`, `test_history_scan_catches_removed_secret` |
| Baseline hides old findings, even after a line shift, but not new ones | `test_baseline_roundtrip_hides_old_but_not_new`                                                |
| `.secretscan.toml` allowlist works                                     | `test_allowlist_config`                                                                        |
| Exit code `2` on a bad baseline path or a non-git repo                 | `test_bad_baseline_path_is_an_error`, `test_not_a_git_repo_is_an_error`                        |
| `install-hook` refuses to overwrite, and the hook blocks a secret      | `test_install_hook_and_precommit_blocks_secret`                                                |

The history tests build real temporary git repositories. Fixture secrets in [conftest.py](tests/conftest.py) are assembled at runtime so the repo never trips its own scanner.

## Real-world tests

`realworld/` clones real repositories and scans their full history. It is kept out of the normal `pytest` run because it needs network access and time.

```bash
pytest realworld                 # every repo in realworld/repos.toml and repos.local.toml
pytest realworld -k django       # just one
```

It checks that the scan finishes in time, stays within `max_findings`, finds at least `min_findings` in a repo with a known leak, and that no raw secret appears in the text, JSON or SARIF output. Findings are printed at the end of the run and saved, redacted, to `realworld/reports/` (git-ignored).

Add public repos to [repos.toml](realworld/repos.toml). Your own repos go in `realworld/repos.local.toml` (git-ignored), copied from [repos.local.example.toml](realworld/repos.local.example.toml); a local `path` is scanned in place. A weekly [workflow](.github/workflows/realworld.yml) runs the public ones.

## Releasing

1. In `CHANGELOG.md`, rename `[Unreleased]` to the new version and date, and add a fresh `[Unreleased]` above it.
2. Bump `__version__` in `src/secretscan/__init__.py`, the only place the version lives.
3. Commit as `(chore): release X.Y.Z`, then `git tag vX.Y.Z && git push --tags`.
4. The tag triggers [release.yml](.github/workflows/release.yml), which publishes to PyPI (trusted publishing, no token) and builds the Docker image.

A published tag is never moved or reused. Fix forward with a new version.
