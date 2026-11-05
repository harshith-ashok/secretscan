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