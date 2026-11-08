"""One positive and some near-miss negatives per rule.

Fake secrets are built at runtime from a seeded RNG, so the repo never contains a literal
token and the vendor prefixes are split ("sk_" + "live_") to stay clear of scanners.
"""

import random
import string

import pytest

from secretscan.engine import scan_chunk
from secretscan.models import Chunk

ALNUM = string.ascii_letters + string.digits
ALNUM_ = ALNUM + "_-"
ALNUM_U = ALNUM + "_"  # no hyphen: GitHub fine-grained tokens use only these
B64 = ALNUM + "+/"
HEX = "0123456789abcdef"
_rng = random.Random(1234)


def rnd(alphabet: str, n: int) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def ids(text: str) -> list[str]:
    return [f.rule_id for f in scan_chunk(Chunk(text, "src/app.py", 1))]


POSITIVES = [
    ("github-fine-grained-token", "github_" + "pat_" + rnd(ALNUM_U, 60)),
    ("gitlab-token", "glpat" + "-" + rnd(ALNUM_, 20)),
    ("google-api-key", "AIza" + rnd(ALNUM_, 35)),
    ("google-oauth-client-secret", "GOCSPX" + "-" + rnd(ALNUM_, 28)),
    ("azure-storage-key", "AccountName=x;AccountKey=" + rnd(B64, 86) + "=="),
    ("digitalocean-token", "dop_" + "v1_" + rnd(HEX, 64)),
    ("stripe-live-key", "sk_" + "live_" + rnd(ALNUM, 24)),
    ("stripe-live-key", "rk_" + "live_" + rnd(ALNUM, 24)),
    (
        "slack-webhook",
        "https://hooks.slack"
        + ".com/services/T"
        + rnd(ALNUM, 8)
        + "/B"
        + rnd(ALNUM, 9)
        + "/"
        + rnd(ALNUM, 24),
    ),
    (
        "discord-webhook",
        "https://discord" + ".com/api/webhooks/" + rnd(string.digits, 18) + "/" + rnd(ALNUM_, 60),
    ),
    ("telegram-bot-token", rnd(string.digits, 9) + ":" + rnd(ALNUM_, 35)),
    ("sendgrid-key", "SG" + "." + rnd(ALNUM_, 22) + "." + rnd(ALNUM_, 43)),
    ("twilio-api-key", "SK" + rnd(HEX, 32)),
    ("mailgun-key", "key" + "-" + rnd(HEX, 32)),
    ("shopify-token", "shpat" + "_" + rnd(HEX, 32)),
    ("npm-token", "npm" + "_" + rnd(ALNUM, 36)),
    ("pypi-token", "pypi-AgEIcHlwaS5vcmc" + rnd(ALNUM_, 60)),
    ("anthropic-key", "sk-" + "ant-" + rnd(ALNUM_, 40)),
    ("openai-key", "sk-" + "proj-" + rnd(ALNUM_, 48)),
    ("huggingface-token", "hf" + "_" + rnd(ALNUM, 34)),
    ("private-key", "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("private-key", "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ("private-key", "-----BEGIN PRIVATE KEY-----"),
    ("aws-secret-access-key", 'aws_secret_access_key = "' + rnd(B64, 40) + '"'),
    ("url-credentials", "DATABASE = postgres://app:" + rnd(ALNUM, 16) + "@db.internal:5432/prod"),
    ("auth-header", "Authorization: Bearer " + rnd(ALNUM, 40)),
    ("generic-credential", 'PASSWORD = "Im_a_Teapot42"'),
    ("generic-credential", "password = 'correct-horse-battery'"),
]


@pytest.mark.parametrize(("rule_id", "text"), POSITIVES, ids=[p[0] for p in POSITIVES])
def test_rule_detects_its_format(rule_id, text):
    assert ids(text)[0] == rule_id


NEGATIVES = [
    "sk_live_short",  # prefix without enough characters
    "ghp_short",
    "AIzaShort",
    "x = 'sk-' + 'this-is-a-very-long-kebab-case-slug-for-a-docs-page'",
    "see sk-learn-the-very-long-slug-name-of-this-documentation-page-here",
    "DB = postgres://user:password@localhost/db",  # textbook placeholder password
    "DB = postgres://user:${DB_PASS}@host/db",  # interpolated, not a literal
    "see https://example.com/some/path",
    "Authorization: Bearer <token>",
    "Authorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaa",  # too regular
    "build 1700000000:1234567890",  # a timestamp pair is not a Telegram token
]


@pytest.mark.parametrize("text", NEGATIVES)
def test_near_misses_are_not_flagged(text):
    assert ids(text) == []


GENERIC_FALSE_POSITIVES = [
    "User(id=1, password='sha1$a45da$e2c7ddc1ed0a1ad4f1a3a6f2d0b6c1d5e8f7a9b0')",  # stored hash
    'password = "md5$salt$0123456789abcdef0123456789abcdef"',
    'self.client.login(username="normaluser", password="normaluser")',  # plain word
    "password = 'mypassword'",
    'token: "token"',  # value is just the key name
    "token = '%HOME\\\\' + token[2:]",  # code, not a credential
    "password = '%(password)s'",  # format string
    'password = "{{ db_password }}"',  # template
    "password = '${DB_PASSWORD}'",  # interpolation
]


@pytest.mark.parametrize("text", GENERIC_FALSE_POSITIVES)
def test_generic_rule_ignores_hashes_code_and_plain_words(text):
    assert "generic-credential" not in ids(text)


def test_specific_rule_beats_the_env_rule():
    key = "sk_" + "live_" + rnd(ALNUM, 32)
    [f] = scan_chunk(Chunk(f"REST={key}", ".env", 1))
    assert (f.rule_id, f.confidence) == ("stripe-live-key", "high")


def test_anthropic_key_is_not_reported_as_openai():
    assert ids("KEY = " + "sk-" + "ant-" + rnd(ALNUM_, 40)) == ["anthropic-key"]
