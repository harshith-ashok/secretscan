# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- 22 new detection rules, 29 in total: GitHub fine-grained tokens, GitLab tokens, Google API
  keys and OAuth client secrets, Azure storage keys, DigitalOcean tokens, Stripe live keys,
  Slack and Discord webhooks, Telegram bot tokens, SendGrid, Twilio, Mailgun and Shopify keys,
  npm and PyPI tokens, Anthropic, OpenAI and Hugging Face keys, AWS secret access keys,
  passwords embedded in URLs, and hard-coded `Authorization` header tokens.
- Private key detection now also covers `ENCRYPTED` and `PGP` key blocks.
- `--min-confidence low|medium|high` to report only findings at or above a confidence level.
  It also drives the exit code, so CI can gate on stronger matches.
- Rules can carry a `validator` for checks a regex cannot express.
- `SECURITY.md` with how secrets are handled and how to report a vulnerability privately.
- A "Detection coverage" table in the README, listing every rule and its confidence.

### Changed

- Releases are distributed through GitHub, not PyPI: the release workflow attaches the wheel
  and sdist to a GitHub Release and builds the container image. Install with
  `pipx install git+https://github.com/harshith-ashok/secretscan`.
- The GitHub Action installs from its own checkout, so `uses: ...@v0.1.0` runs exactly that
  version. The `version` input is removed.
- The generic credential rule is much stricter. It no longer reports stored password hashes
  (`sha1$...`, bcrypt, argon2), code or template strings (`%(password)s`, `{{ x }}`, `${X}`),
  values equal to the key name (`token: "token"`), or plain single-class words
  (`password="normaluser"`). On Django's full history this cut findings from 301 to 16.
- A specific rule now wins over the `.env` rule, so a committed Stripe live key in a `.env`
  file is reported as high confidence instead of medium.
- Scans are slower on large histories because there are more rules to run. Django's full
  history went from about 23 seconds to 45.

## [0.1.0] - 2026-11-08

First release.

### Added

- Scan the working tree, staged changes (`--staged`) or the full git history (`--history`).
- Seven rules: AWS access key IDs, GitHub tokens, Slack tokens, private key headers, JWTs,
  unquoted `.env`-style secrets and a generic credential assignment rule.
- Opt-in Shannon entropy detector (`--entropy`).
- Every finding carries a file cite, confidence, a masked copy of the matched line and a
  rule-specific suggestion. Raw secrets never appear in any output.
- Text, JSON and SARIF 2.1.0 output.
- Baselines (`--baseline`, `--write-baseline`) that survive code moving, and a
  `.secretscan.toml` allowlist.
- `install-hook` for a git pre-commit hook, and a pre-commit framework hook.
- Reusable GitHub Action with optional SARIF upload, a Docker image and a release
  workflow.
- A real-world test suite that clones public repositories and scans their history.

[Unreleased]: https://github.com/harshith-ashok/secretscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/harshith-ashok/secretscan/releases/tag/v0.1.0
