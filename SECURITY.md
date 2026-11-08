# Security policy

`secretscan` handles other people's credentials, so it is built to be safe by default.

## How it treats what it finds

- Scanning is local. It makes no network requests and has no runtime dependencies.
- Raw secrets are never printed. Every report shows only the first 4 and last 2 characters,
  and the matched line has every secret on it masked. `Finding.__repr__` omits the secret too.
- It only reads: it does not modify files, history or the git configuration. `install-hook` is
  the one command that writes, and only to the hook file.

## Reporting a vulnerability

Please report privately rather than in a public issue.

1. Go to the repository's **Security** tab and choose **Report a vulnerability**
   (GitHub private vulnerability reporting).
2. Include the version (`secretscan --version`), what you did, what you expected and what
   happened. A minimal repository or input that reproduces it helps most.

I aim to acknowledge a report within 7 days and to ship a fix or a mitigation as soon as I
can. This is a one-person project, so there is no guaranteed turnaround. Reporters are
credited in the changelog unless they prefer not to be.

### What counts as a vulnerability

- Any output, log, exception or file that exposes more of a secret than the redacted form.
- Command or argument injection through a path, revision or option (it shells out to `git`).
- A rule or filter that can be made to hang (catastrophic regex backtracking) on crafted input.
- The installed hook, GitHub Action or Docker image doing something beyond what is documented.

### What does not

A missed secret (false negative) or a wrong alert (false positive) is a normal bug. Open a
public issue, but do not paste a real secret into it. Use a fake value of the same shape.

## Supported versions

Fixes go to the latest release. Please upgrade before reporting.

## If secretscan finds a real secret

Treat it as compromised and rotate it first. Deleting it from the latest commit does not
remove it from history, and anyone who has cloned the repository still has it.
