from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

Validator = Callable[[str, "re.Match[str]"], bool]


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    group: int = 0  # which regex group holds the secret itself
    min_entropy: float | None = None  # drop matches that look too regular
    confidence: str = "high"  # how likely a match is a real secret: high | medium | low
    advice: str = "Rotate it, then load it from an environment variable or secret manager."
    validator: Validator | None = None  # extra check on (secret, match); False drops the match


def revoke(where: str) -> str:
    return (
        f"Revoke it {where} and issue a new one. "
        "Keep it in an environment variable or secret manager, not in code."
    )


# --------------------------------------------------------------------------- validators
_HASHED = re.compile(
    r"^(?:(?:md5|sha1|sha256|sha512|pbkdf2_sha\d+|bcrypt(?:_sha256)?|argon2|scrypt|crypt)\$"
    r"|\$(?:2[abxy]|argon2\w*|[156])\$)"
)
_CODE_LIKE = re.compile(r"[()\[\]{}<>|\\]|%[(sd]|\$\{|\{\{")
_WEAK_URL_PASSWORDS = {"pass", "password", "passwd", "secret", "root", "admin", "user", "test"}


def _norm(s: str) -> str:
    return s.lower().replace("-", "").replace("_", "")


def plausible_credential(secret: str, m: re.Match[str]) -> bool:
    """Drop what a human would not call a credential: hashes, code, key names, plain words."""
    if _HASHED.match(secret) or _CODE_LIKE.search(secret):
        return False  # Django-style stored hashes, templates, format strings, code
    if _norm(secret) == _norm(m.group(1)):
        return False  # token: "token"
    classes = sum(bool(re.search(p, secret)) for p in ("[a-z]", "[A-Z]", "[0-9]", "[^A-Za-z0-9]"))
    return classes >= 2  # real secrets mix character classes; "normaluser" does not


def real_url_password(secret: str, m: re.Match[str]) -> bool:
    return secret.lower() not in _WEAK_URL_PASSWORDS


BUILTIN_RULES: tuple[Rule, ...] = (
    # ---- cloud and source hosting: rigid prefixes, so high confidence
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        group=1,
        advice=(
            "Deactivate this key in IAM and create a new one. "
            "Prefer an IAM role or environment credentials over keys in code."
        ),
    ),
    Rule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        group=1,
        advice=(
            "Revoke it at github.com/settings/tokens and create a new one. "
            "Read it from an environment variable or an Actions secret."
        ),
    ),
    Rule(
        "github-fine-grained-token",
        "GitHub fine-grained personal access token",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,})\b"),
        group=1,
        advice=revoke("at github.com/settings/personal-access-tokens"),
    ),
    Rule(
        "gitlab-token",
        "GitLab personal access token",
        re.compile(r"\b(glpat-[A-Za-z0-9_-]{20})\b"),
        group=1,
        advice=revoke("in GitLab (User settings > Access tokens)"),
    ),
    Rule(
        "google-api-key",
        "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        group=1,
        advice=revoke("in the Google Cloud console (APIs & Services > Credentials)")
        + " Restrict new keys by API and referrer.",
    ),
    Rule(
        "google-oauth-client-secret",
        "Google OAuth client secret",
        re.compile(r"\b(GOCSPX-[A-Za-z0-9_-]{28})\b"),
        group=1,
        advice=revoke("by resetting the client secret in the Google Cloud console"),
    ),
    Rule(
        "azure-storage-key",
        "Azure storage account key",
        re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/]{40,}={0,2})"),
        group=1,
        advice=revoke(
            "by regenerating the key in the Azure portal (Storage account > Access keys)"
        ),
    ),
    Rule(
        "digitalocean-token",
        "DigitalOcean token",
        re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"),
        group=1,
        advice=revoke("in the DigitalOcean control panel (API > Tokens)"),
    ),
    # ---- payments, messaging and SaaS
    Rule(
        "stripe-live-key",
        "Stripe live secret or restricted key",
        re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b"),
        group=1,
        advice=revoke("in the Stripe dashboard (Developers > API keys)")
        + " Check the logs for use.",
    ),
    Rule(
        "slack-token",
        "Slack token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        group=1,
        advice=(
            "Revoke the token in your Slack app settings and issue a new one. "
            "Keep it in a secret manager, not in code."
        ),
    ),
    Rule(
        "slack-webhook",
        "Slack incoming webhook URL",
        re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)"
        ),
        group=1,
        advice=revoke("by deleting the webhook in your Slack app settings"),
    ),
    Rule(
        "discord-webhook",
        "Discord webhook URL",
        re.compile(r"(https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)"),
        group=1,
        advice=revoke("by deleting the webhook in the channel's integration settings"),
    ),
    Rule(
        "telegram-bot-token",
        "Telegram bot token",
        re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b"),
        group=1,
        min_entropy=4.0,
        advice=revoke("by sending /revoke to @BotFather"),
    ),
    Rule(
        "sendgrid-key",
        "SendGrid API key",
        re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
        group=1,
        advice=revoke("in SendGrid (Settings > API Keys)"),
    ),
    Rule(
        "twilio-api-key",
        "Twilio API key SID",
        re.compile(r"\b(SK[0-9a-f]{32})\b"),
        group=1,
        advice=revoke("in the Twilio console (Account > API keys)"),
    ),
    Rule(
        "mailgun-key",
        "Mailgun API key",
        re.compile(r"\b(key-[0-9a-f]{32})\b"),
        group=1,
        advice=revoke("in the Mailgun dashboard (API security)"),
    ),
    Rule(
        "shopify-token",
        "Shopify access token",
        re.compile(r"\b(shp(?:at|ca|pa|ss)_[a-f0-9]{32})\b"),
        group=1,
        advice=revoke("in the Shopify admin (Apps > Develop apps)"),
    ),
    # ---- package registries
    Rule(
        "npm-token",
        "npm access token",
        re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        group=1,
        advice=revoke("with `npm token revoke` or on npmjs.com (Access Tokens)"),
    ),
    Rule(
        "pypi-token",
        "PyPI API token",
        re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"),
        group=1,
        advice=revoke("at pypi.org/manage/account (API tokens)"),
    ),
    # ---- AI providers (Anthropic first: its keys also look like the generic `sk-` form)
    Rule(
        "anthropic-key",
        "Anthropic API key",
        re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"),
        group=1,
        advice=revoke("in the Anthropic Console (Settings > API keys)"),
    ),
    Rule(
        "openai-key",
        "OpenAI API key",
        re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})\b"),
        group=1,
        min_entropy=4.2,  # keeps out long kebab-case slugs that start with `sk-`
        advice=revoke("on platform.openai.com (API keys)"),
    ),
    Rule(
        "huggingface-token",
        "Hugging Face access token",
        re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"),
        group=1,
        advice=revoke("at huggingface.co/settings/tokens"),
    ),
    # ---- keys and certificates
    Rule(
        "private-key",
        "Private key block",
        re.compile(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)"
        ),
        group=1,
        advice=(
            "Treat this key pair as compromised: generate a new one and replace the public key "
            "wherever it was installed. Keep private keys out of the repo."
        ),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        group=1,
        confidence="medium",
        advice=(
            "If this is a live token, revoke the session or rotate the signing key. "
            "If it is a sample, mark the line with `# secretscan:ignore`."
        ),
    ),
    # ---- credentials embedded in common syntax (medium: format is looser than a vendor prefix)
    Rule(
        "aws-secret-access-key",
        "AWS secret access key",
        re.compile(r"(?i)\baws_?secret_?(?:access_?)?key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"),
        group=1,
        min_entropy=4.0,
        confidence="medium",
        advice=(
            "Deactivate the access key it belongs to in IAM and create a new pair. "
            "Prefer an IAM role over keys in code."
        ),
    ),
    Rule(
        "url-credentials",
        "Password embedded in a URL",
        re.compile(
            r"\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@'\"<>]{1,64}:([^\s:/@'\"<>{}$]{4,64})@[\w.-]+"
        ),
        group=1,
        validator=real_url_password,
        confidence="medium",
        advice=(
            "Change the password, and pass credentials separately (environment variable, "
            "credential helper or secret manager) instead of inside the URL."
        ),
    ),
    Rule(
        "auth-header",
        "Hard-coded Authorization header token",
        re.compile(
            r"(?i)\bauthorization\b['\"]?\s*[:=]\s*['\"]?(?:basic|bearer)\s+([A-Za-z0-9+/=._-]{20,})"
        ),
        group=1,
        min_entropy=3.5,
        confidence="medium",
        advice=(
            "If this is a real credential, revoke it and read it from the environment. "
            "Sample tokens in docs can be marked `# secretscan:ignore`."
        ),
    ),
    # Unquoted `.env`-style assignment: NAME=<long random-looking value>, whatever NAME is.
    # Entropy >= 4.0 keeps out hex hashes (capped at 4.0), words and paths.
    Rule(
        "env-secret",
        "Unquoted secret assignment",
        re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*([A-Za-z0-9+/_-]{20,})\s*$"),
        group=1,
        min_entropy=4.0,
        confidence="medium",
        advice=(
            "Add the file to .gitignore, commit a .env.example with placeholders instead, "
            "and rotate the value if it was ever committed."
        ),
    ),
    # Most general rule last, so specific rules win when both match the same secret.
    Rule(
        "generic-credential",
        "Hard-coded credential assignment",
        re.compile(
            r"""(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
        ),
        group=2,
        min_entropy=3.0,
        validator=plausible_credential,
        confidence="low",
        advice=(
            "If it is real, rotate it and load it from the environment. "
            "If it is a test value, allowlist the path in .secretscan.toml "
            "or mark the line `# secretscan:ignore`."
        ),
    ),
)
