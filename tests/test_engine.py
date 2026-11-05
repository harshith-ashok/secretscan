from secretscan.engine import scan_chunk
from secretscan.models import Chunk


def run(text, **kw):
    return list(scan_chunk(Chunk(text, "f.py", 3), **kw))


def test_detects_aws_key_with_location(aws_key):
    [f] = run(f"key = {aws_key}")
    assert (f.rule_id, f.path, f.line, f.secret) == ("aws-access-key-id", "f.py", 3, aws_key)


def test_detects_github_token(gh_token):
    assert [f.rule_id for f in run(f"export GH={gh_token}")] == ["github-token"]


def test_detects_private_key_header():
    assert [f.rule_id for f in run("-----BEGIN RSA PRIVATE KEY-----")] == ["private-key"]


def test_clean_line_has_no_findings():
    assert run("x = compute(1, 2)  # nothing to see") == []


def test_inline_ignore_marker_suppresses(aws_key):
    assert run(f"key = {aws_key}  # secretscan:ignore") == []


def test_placeholder_values_are_skipped():
    assert run('api_key = "your_api_key_here"') == []
    assert run("AKIAIOSFODNN7EXAMPLE") == []


def test_generic_rule_needs_enough_entropy():
    assert [f.rule_id for f in run('password = "correct-horse-battery"')] == ["generic-credential"]
    assert run('password = "aaaaaaaaaaaa"') == []  # entropy 0 -> boring, ignore


def test_specific_rule_wins_over_generic(aws_key):
    ids = [f.rule_id for f in run(f'api_key = "{aws_key}"')]
    assert ids == ["aws-access-key-id"]  # reported once, not twice


def test_entropy_detector_is_opt_in():
    blob = "Zk9xQ2v8Lw3Rt7Yb1Nc5Hd4Jm6Pa0Se"
    assert run(f"data = {blob}") == []
    assert [f.rule_id for f in run(f"data = {blob}", entropy_threshold=4.0)] == ["high-entropy"]


def test_git_sha_is_not_flagged_as_high_entropy():
    sha = "a3f5c9e1b27d4086f1e2c3d4b5a69788c9d0e1f2"  # hex alphabet caps entropy at 4 bits
    assert run(f"commit {sha}", entropy_threshold=4.3) == []


def test_finding_repr_never_contains_the_secret(aws_key):
    [f] = run(aws_key)
    assert aws_key not in repr(f)
    assert aws_key not in f.redacted