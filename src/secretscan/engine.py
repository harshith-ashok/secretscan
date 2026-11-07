from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath

from .entropy import TOKEN_RE, shannon_entropy
from .models import Chunk, Finding, mask_line
from .rules import BUILTIN_RULES, Rule

IGNORE_MARKER = "secretscan:ignore"
MAX_LINE = 4000  # skip absurdly long lines (minified JS): bounds regex cost
PLACEHOLDERS = ("example", "changeme", "your_", "<", "xxxx", "placeholder", "dummy")


def looks_like_placeholder(secret: str) -> bool:
    low = secret.lower()
    return any(p in low for p in PLACEHOLDERS)


LEVELS = ("low", "medium", "high")
NON_PROD_DIRS = {
    "test",
    "tests",
    "testing",
    "fixture",
    "fixtures",
    "doc",
    "docs",
    "example",
    "examples",
}
ENTROPY_ADVICE = (
    "Check whether this is a real secret or just an ID or hash. If it is real, rotate it;"
    " if not, mark the line `# secretscan:ignore`."
)


def adjust_confidence(confidence: str, path: str) -> str:
    """Fake credentials live in tests and docs, so drop one level for those paths."""
    p = PurePosixPath(path.lower())
    in_non_prod = bool(NON_PROD_DIRS & set(p.parts[:-1])) or p.name.startswith("test_")
    if not in_non_prod:
        return confidence
    return LEVELS[max(0, LEVELS.index(confidence) - 1)]


def suggestion(advice: str, commit: str | None) -> str:
    if not commit:
        return advice
    return (
        f"{advice} It is in git history (commit {commit[:8]}), so deleting the line is not enough."
    )


def scan_chunk(
    chunk: Chunk,
    rules: Iterable[Rule] = BUILTIN_RULES,
    entropy_threshold: float | None = None,
) -> Iterator[Finding]:
    text = chunk.text
    if len(text) > MAX_LINE or IGNORE_MARKER in text:
        return

    seen: set[str] = set()
    hits: list[tuple[str, str, str, str, str]] = []  # rule id, description, secret, conf, advice

    for rule in rules:
        for m in rule.pattern.finditer(text):
            secret = m.group(rule.group)
            if secret in seen or looks_like_placeholder(secret):
                continue
            if rule.min_entropy is not None and shannon_entropy(secret) < rule.min_entropy:
                continue
            seen.add(secret)
            hits.append((rule.id, rule.description, secret, rule.confidence, rule.advice))

    if entropy_threshold is not None:
        for m in TOKEN_RE.finditer(text):
            token = m.group(0)
            if token in seen or looks_like_placeholder(token):
                continue
            if shannon_entropy(token) >= entropy_threshold:
                seen.add(token)
                hits.append(("high-entropy", "High-entropy string", token, "low", ENTROPY_ADVICE))

    # Mask every secret on the line in every finding's context, so none can leak another.
    context = mask_line(text, [h[2] for h in hits]) if hits else ""
    for rule_id, desc, secret, confidence, advice in hits:
        yield Finding(
            rule_id,
            desc,
            chunk.path,
            chunk.line,
            secret,
            chunk.commit,
            confidence=adjust_confidence(confidence, chunk.path),
            suggestion=suggestion(advice, chunk.commit),
            context=context,
        )


def scan_chunks(
    chunks: Iterable[Chunk],
    rules: Iterable[Rule] = BUILTIN_RULES,
    entropy_threshold: float | None = None,
) -> Iterator[Finding]:
    rules = tuple(rules)  # allow any iterable, iterate many times
    for chunk in chunks:
        yield from scan_chunk(chunk, rules, entropy_threshold)
