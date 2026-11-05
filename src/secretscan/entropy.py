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
