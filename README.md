<h3 align="center">secretscan</h3>

<p align="center">Find leaked secrets in files, staged changes and git history. Zero dependencies.</p>

---

Git never forgets: deleting a secret in a later commit leaves it in history. `secretscan` checks all three places a secret can live, and every behaviour below is backed by a test.

![architecture](figs/architecture.png)

## Install

Requires Python 3.11+ and `git` on `PATH`.

```bash
pip install -e ".[dev]"
```

## Usage

```bash
secretscan scan .                          # files on disk
secretscan scan . --staged                 # staged changes only
secretscan scan . --history                # every commit
secretscan scan . --history main~20..HEAD  # a revision range
secretscan scan . --entropy 4.5            # also flag random-looking tokens
secretscan scan . --format sarif --output results.sarif
secretscan install-hook .                  # block commits that add secrets
```

| Exit code | Meaning                                    |
| --------- | ------------------------------------------ |
| `0`       | clean                                      |
| `1`       | findings reported                          |
| `2`       | error (bad path, not a git repo, git fail) |

Other flags: `--format text|json|sarif`, `--baseline FILE`, `--write-baseline FILE`.

## Tests

```bash
pytest                                              # 28 tests
pytest --cov=secretscan --cov-report=term-missing   # CI requires >= 90%
ruff check . && ruff format --check . && mypy
```

Each behaviour maps to a test:

| Behaviour                                                        | Test                                                                               |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Detects AWS keys, GitHub tokens and private key headers          | `test_engine.py::test_detects_*`                                                   |
| Reports the right rule, path and line                            | `test_detects_aws_key_with_location`                                               |
| `# secretscan:ignore` suppresses a line                          | `test_inline_ignore_marker_suppresses`                                             |
| Placeholders (`example`, `your_`, ...) are skipped               | `test_placeholder_values_are_skipped`                                              |
| Generic `password = "..."` needs entropy >= 3.0                  | `test_generic_rule_needs_enough_entropy`                                           |
| A specific rule wins over the generic one (one finding, not two) | `test_specific_rule_wins_over_generic`                                             |
| Entropy detector is opt-in; git SHAs never trip it               | `test_entropy_detector_is_opt_in`, `test_git_sha_is_not_flagged_as_high_entropy`   |
| Entropy is 0 to log2(distinct symbols) for any string            | `test_entropy.py` (includes a Hypothesis property test)                            |
| The raw secret never appears in `repr`, text or SARIF output     | `test_finding_repr_never_contains_the_secret`, `test_sarif_output_shape_and_no_raw_secret` |
| Diff parser tracks path, line and commit; `+++` in content is data | `test_parse_diff_tracks_paths_lines_and_commit`                                  |
| Worktree scan skips binary, `.git` and oversized files           | `test_worktree_skips_binary_git_and_big_files`                                     |
| Staged scan sees only staged additions                           | `test_staged_only_sees_staged_additions`                                           |
| History finds a line that was later deleted                      | `test_history_finds_lines_that_were_later_deleted`, `test_history_scan_catches_removed_secret` |
| Baseline hides old findings (even after a line shift), not new ones | `test_baseline_roundtrip_hides_old_but_not_new`                                 |
| `.secretscan.toml` allowlist works                               | `test_allowlist_config`                                                            |
| Exit code `2` on bad baseline path or non-git repo               | `test_bad_baseline_path_is_an_error`, `test_not_a_git_repo_is_an_error`            |
| `install-hook` refuses to overwrite, and the hook blocks a secret | `test_install_hook_and_precommit_blocks_secret`                                   |

The history tests build real temporary git repositories. Fixture secrets in [conftest.py](tests/conftest.py) are assembled at runtime so the repo never trips its own scanner.

## How it works

![engine](figs/engine.png)

Sources, engine and reporters talk only through two immutable types, `Chunk` (one line plus origin) and `Finding` (a suspected secret), so each part is testable alone.

| Module                                      | Role                                       |
| ------------------------------------------- | ------------------------------------------ |
| [sources.py](src/secretscan/sources.py)     | worktree, staged and history to `Chunk`s   |
| [rules.py](src/secretscan/rules.py)         | built-in rules: AWS, GitHub, Slack, private key, JWT, generic credential |
| [engine.py](src/secretscan/engine.py)       | `Chunk`s to `Finding`s, with filters       |
| [entropy.py](src/secretscan/entropy.py)     | Shannon entropy                            |
| [baseline.py](src/secretscan/baseline.py)   | accepted-findings file (line-shift safe)   |
| [config.py](src/secretscan/config.py)       | `.secretscan.toml` allowlist               |
| [reporters.py](src/secretscan/reporters.py) | text, JSON, SARIF                          |
| [cli.py](src/secretscan/cli.py)             | argument parsing, hook installer           |

Sources are lazy generators, so memory stays flat on large repositories.

## CI

[ci.yml](.github/workflows/ci.yml) runs lint (ruff, mypy), a test matrix (Linux, macOS, Windows x Python 3.11-3.13) with a 90% coverage gate, a dogfood job that scans this repo's full history and uploads SARIF, and a build. [release.yml](.github/workflows/release.yml) publishes on `v*` tags. Also provided: a [Dockerfile](Dockerfile), a reusable [action.yml](action.yml) and a [pre-commit hook](.pre-commit-hooks.yml).

## Limitations

- Lines are scanned one at a time, so multi-line secrets are not detected. Private keys match the `BEGIN` header only.
- The placeholder filter is substring-based, so a real secret containing `example` or `<` is dropped.
- Files over 1 MB and lines over 4000 characters are skipped.
- History scanning reads added lines only; merge-commit diffs and binary content are not examined.
- A pre-commit hook can be bypassed with `--no-verify`. CI is the enforcement.
- If a real secret was ever committed, rotate it. Rewriting history is secondary.

## License

MIT
