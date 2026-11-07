import json

from secretscan.engine import scan_chunk
from secretscan.models import Chunk
from secretscan.reporters import to_json, to_sarif, to_text


def findings(aws_key):
    return list(scan_chunk(Chunk(f"KEY = '{aws_key}'", "app.py", 7, "67632ec2abcdef")))


def test_text_report_has_cite_confidence_match_and_suggestion(aws_key):
    out = to_text(findings(aws_key))
    assert "app.py:7  [aws-access-key-id]" in out and "(commit 67632ec2)" in out
    assert "confidence: high" in out
    assert "match:      KEY = 'AKIA…90'" in out
    assert "suggestion: Deactivate this key" in out
    assert aws_key not in out


def test_json_report_has_the_new_fields(aws_key):
    [item] = json.loads(to_json(findings(aws_key)))["findings"]
    assert item["confidence"] == "high"
    assert item["match"] == "KEY = 'AKIA…90'"
    assert item["suggestion"].startswith("Deactivate this key")


def test_sarif_report_carries_snippet_confidence_and_advice(aws_key):
    out = to_sarif(findings(aws_key))
    [result] = json.loads(out)["runs"][0]["results"]
    assert result["properties"] == {"confidence": "high"}
    assert "Deactivate this key" in result["message"]["text"]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["snippet"]["text"] == "KEY = 'AKIA…90'"
    assert aws_key not in out
