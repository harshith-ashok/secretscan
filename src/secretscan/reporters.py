# pure functions `list[Finding] -> str`

from __future__ import annotations

import json
from collections.abc import Sequence

from . import __version__
from .models import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def to_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return "No secrets found.\n"
    lines = []
    for f in findings:
        where = f"{f.path}:{f.line}"
        commit = f"  (commit {f.commit[:8]})" if f.commit else ""
        lines.append(f"{where}  [{f.rule_id}] {f.description}  {f.redacted}{commit}")
        lines.append(f"    confidence: {f.confidence}")
        lines.append(f"    match:      {f.context}")
        lines.append(f"    suggestion: {f.suggestion}")
        lines.append("")
    lines.append(f"{len(findings)} potential secret(s) found.")
    return "\n".join(lines) + "\n"


def to_json(findings: Sequence[Finding]) -> str:
    items = [
        {
            "rule": f.rule_id,
            "path": f.path,
            "line": f.line,
            "commit": f.commit,
            "secret": f.redacted,
            "confidence": f.confidence,
            "match": f.context,
            "suggestion": f.suggestion,
            "fingerprint": f.fingerprint,
        }
        for f in findings
    ]
    return json.dumps({"findings": items}, indent=2) + "\n"


def to_sarif(findings: Sequence[Finding]) -> str:
    rules = {f.rule_id: f.description for f in findings}
    results = [
        {
            "ruleId": f.rule_id,
            "level": "error",
            "message": {"text": f"{f.description} ({f.redacted}). {f.suggestion}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line, "snippet": {"text": f.context}},
                    }
                }
            ],
            "partialFingerprints": {"secretscan/v1": f.fingerprint},
            "properties": {"confidence": f.confidence},
        }
        for f in findings
    ]
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretscan",
                        "version": __version__,
                        "rules": [
                            {"id": rid, "shortDescription": {"text": d}}
                            for rid, d in sorted(rules.items())
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif}
