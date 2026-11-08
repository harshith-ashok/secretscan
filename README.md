<h1 align="center">secretscan</h1>

<p align="center">Find leaked secrets in your files, staged changes and full git history.</p>

<p align="center">
  <a href="https://github.com/harshith-ashok/secretscan/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/harshith-ashok/secretscan/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-0-brightgreen">
</p>

Git never forgets: deleting a secret in a later commit leaves it in history, where anyone who can clone the repo can read it. `secretscan` checks every place a secret can live and tells you what to do about each one.

- **Three scopes:** working tree, staged changes, and every commit in history, including lines since deleted.
- **29 rules** for cloud, payment, messaging, package-registry and AI-provider credentials, plus private keys, JWTs, `.env` files and passwords in URLs. An opt-in entropy detector catches the rest.
- **Actionable findings:** each one has a file cite, a confidence level, the matched line and a suggestion for fixing it.
- **Safe by default:** no raw secret is ever printed, logged or written to a report.
- **Fits your workflow:** pre-commit hook, GitHub Action with code-scanning upload, Docker image, text/JSON/SARIF output, baselines and allowlists.
- **No dependencies.** Python 3.11+ and `git`, on Linux, macOS and Windows.

## Quick start

```bash
pipx install git+https://github.com/harshith-ashok/secretscan
cd your-repo
secretscan scan . --history
```

```text
app.py:1  [aws-access-key-id] AWS access key ID  AKIA…90  (commit 67632ec2)
    confidence: high
    match:      KEY = 'AKIA…90'
    suggestion: Deactivate this key in IAM and create a new one. Prefer an IAM role or
                environment credentials over keys in code. It is in git history (commit
                67632ec2), so deleting the line is not enough.

1 potential secret(s) found.
```

If it reports a real secret, **rotate it first**. Removing it from the latest commit does not remove it from history.

## Installation

```bash
pipx install git+https://github.com/harshith-ashok/secretscan          # latest
pipx install git+https://github.com/harshith-ashok/secretscan@v0.1.0   # a specific release
uvx --from git+https://github.com/harshith-ashok/secretscan secretscan scan .   # no install
docker run --rm -v "$PWD:/repo" ghcr.io/harshith-ashok/secretscan scan . --history
```

`pip install git+https://github.com/harshith-ashok/secretscan` works too, and each [release](https://github.com/harshith-ashok/secretscan/releases) has a wheel to download.

## Usage

```bash
secretscan scan .                          # files on disk
secretscan scan . --staged                 # staged changes only
secretscan scan . --history                # every commit
secretscan scan . --history main~20..HEAD  # a revision range
secretscan scan . --entropy 4.5            # also flag random-looking tokens
secretscan scan . --min-confidence medium  # drop low-confidence matches
secretscan scan . --format sarif --output results.sarif
secretscan install-hook .                  # block commits that add secrets
```

| Option                               | Meaning                                           |
| ------------------------------------ | ------------------------------------------------- |
| `--staged` / `--history [REV...]`    | scan staged changes / commits instead of files    |
| `--entropy BITS`                     | also flag random-looking tokens (try `4.5`)       |
| `--min-confidence low\|medium\|high` | report only findings at or above this confidence  |
| `--format text\|json\|sarif`         | output format (default `text`)                    |
| `--output FILE`                      | write the report to a file instead of stdout      |
| `--baseline FILE`                    | ignore findings recorded in this baseline         |
| `--write-baseline FILE`              | record current findings as the baseline, exit `0` |

| Exit code | Meaning                                       |
| --------- | --------------------------------------------- |
| `0`       | clean                                         |
| `1`       | findings reported                             |
| `2`       | error (bad path, not a git repo, git failure) |

### Reading a finding

| Field          | What it tells you                                                                   |
| -------------- | ----------------------------------------------------------------------------------- |
| **cite**       | `path:line`, plus the commit for history findings                                   |
| **confidence** | how likely it is real: `high` for rigid vendor formats, `medium` for looser syntax (JWTs, `.env`, URL passwords, auth headers), `low` for generic and entropy matches |
| **match**      | the source line with every secret masked (first 4 and last 2 characters shown)      |
| **suggestion** | what to do next, specific to the rule                                               |

Confidence drops one level for files under `tests/`, `docs/`, `examples/` and similar, where fake credentials are common. JSON and SARIF carry the same fields.

## Configuration

**Allowlist.** Put a `.secretscan.toml` in the scanned directory:

```toml
[allowlist]
paths   = ["tests/fixtures/*", "docs/*"]   # glob patterns on the finding's path
regexes = ["^test_"]                       # regexes matched against the secret
```

**Inline ignore.** Add `# secretscan:ignore` to a line to suppress everything on it.

**Baseline.** Adopt the scanner on an old repo without failing on history you can't change:

```bash
secretscan scan . --history --write-baseline .secretscan-baseline.json   # once, then commit it
secretscan scan . --baseline .secretscan-baseline.json                   # in CI: only new findings fail
```

Baselines fingerprint the rule, path and secret, not the line number, so they survive code moving.

## Integrations

### GitHub Action

```yaml
# .github/workflows/secrets.yml
name: secrets
on: [push, pull_request]
permissions:
  contents: read
  security-events: write # only needed for upload-sarif
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 } # history scan needs every commit
      - uses: harshith-ashok/secretscan@main   # or pin a release tag, once one includes this action
        with:
          upload-sarif: "true" # findings appear under Security > Code scanning
```

| Input          | Default | Meaning                                                                  |
| -------------- | ------- | ------------------------------------------------------------------------ |
| `path`         | `.`     | what to scan                                                             |
| `history`      | `true`  | also scan full git history                                               |
| `args`         | `""`    | extra flags, e.g. `--baseline .secretscan-baseline.json`                 |
| `upload-sarif` | `false` | upload to GitHub code scanning (needs code scanning enabled on the repo) |

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/harshith-ashok/secretscan
    rev: v0.1.0
    hooks:
      - id: secretscan
```

Or install a plain git hook: `secretscan install-hook .`. A hook can be bypassed with `git commit --no-verify`, so CI is the real enforcement.

### As a library

```python
from pathlib import Path
from secretscan.engine import scan_chunks
from secretscan.sources import iter_history

for f in scan_chunks(iter_history(Path("."))):
    print(f.rule_id, f.confidence, f"{f.path}:{f.line}", f.redacted)
```

`iter_worktree` and `iter_staged` work the same way, and the package ships type hints.

## Detection coverage

29 built-in rules, most specific first. A secret is reported once, by the first rule that matches it.

| Rule                         | Detects                                                    | Confidence |
| ---------------------------- | ---------------------------------------------------------- | ---------- |
| `aws-access-key-id`          | AWS access key ID                                          | high       |
| `github-token`               | GitHub token                                               | high       |
| `github-fine-grained-token`  | GitHub fine-grained personal access token                  | high       |
| `gitlab-token`               | GitLab personal access token                               | high       |
| `google-api-key`             | Google API key                                             | high       |
| `google-oauth-client-secret` | Google OAuth client secret                                 | high       |
| `azure-storage-key`          | Azure storage account key                                  | high       |
| `digitalocean-token`         | DigitalOcean token                                         | high       |
| `stripe-live-key`            | Stripe live secret or restricted key                       | high       |
| `slack-token`                | Slack token                                                | high       |
| `slack-webhook`              | Slack incoming webhook URL                                 | high       |
| `discord-webhook`            | Discord webhook URL                                        | high       |
| `telegram-bot-token`         | Telegram bot token                                         | high       |
| `sendgrid-key`               | SendGrid API key                                           | high       |
| `twilio-api-key`             | Twilio API key SID                                         | high       |
| `mailgun-key`                | Mailgun API key                                            | high       |
| `shopify-token`              | Shopify access token                                       | high       |
| `npm-token`                  | npm access token                                           | high       |
| `pypi-token`                 | PyPI API token                                             | high       |
| `anthropic-key`              | Anthropic API key                                          | high       |
| `openai-key`                 | OpenAI API key                                             | high       |
| `huggingface-token`          | Hugging Face access token                                  | high       |
| `private-key`                | Private key block (RSA, EC, DSA, OpenSSH, PGP, encrypted) | high       |
| `jwt`                        | JSON Web Token                                             | medium     |
| `aws-secret-access-key`      | AWS secret access key                                      | medium     |
| `url-credentials`            | Password embedded in a URL                                 | medium     |
| `auth-header`                | Hard-coded `Authorization` header token                    | medium     |
| `env-secret`                 | Unquoted `NAME=value` secret, as in `.env` files           | medium     |
| `generic-credential`         | Hard-coded `password` / `token` / `api_key` assignment     | low        |

To cut false positives, placeholders (`example`, `changeme`, `<...>`) are skipped, and the generic rule ignores stored password hashes (`sha1$...`, bcrypt, argon2), code and template strings, and plain words.

### Tested on real repositories

The [real-world suite](CONTRIBUTING.md#real-world-tests) scans the full history of public projects and of a private repo with a known leak:

| Repository                           | Findings | What they are                                                                              | Scan time |
| ------------------------------------ | -------- | ------------------------------------------------------------------------------------------ | --------- |
| click                                | 0        |                                                                                            | 0.8 s     |
| flask                                | 0        |                                                                                            | 1.2 s     |
| requests                             | 12       | test private keys and test URL passwords (low and medium confidence), a docs analytics key | 1.6 s     |
| django                               | 16       | hard-coded test passwords, all low confidence                                              | 45 s      |
| private repo with a committed `.env` | 1        | a live Stripe key, **high** confidence                                                     | under 1 s |

## How it works

![engine](https://raw.githubusercontent.com/harshith-ashok/secretscan/main/figs/engine.png)

Three independent stages (sources, engine, reporters) talk only through two small immutable types, `Chunk` (one line plus where it came from) and `Finding` (a suspected secret), so each can be tested and extended alone. Sources are lazy generators, so memory stays flat on huge repositories. History scans read `git log -p` and report exact line numbers from the diff hunks.

## Limitations

- Lines are scanned one at a time, so multi-line secrets are not detected. Private keys match the `BEGIN` header only.
- The placeholder filter is substring-based, so a real secret containing `example` or `<` is dropped.
- Files over 1 MB and lines over 4000 characters are skipped.
- History scanning reads added lines only. Merge-commit diffs and binary content are not examined.
- It finds credentials by format and randomness. It does not check whether one is still live, and it is not a code-vulnerability scanner.

For a much larger rule set or live verification, see tools like [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog). secretscan aims to be small, dependency-free and clear about what to do next.

## Contributing

Bug reports, new rules and fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests and the release process, [CHANGELOG.md](CHANGELOG.md) for what changed, and [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

[MIT](LICENSE)
