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


def test_detects_unquoted_env_file_secret():
    blob = "Zk9xQ2v8Lw3Rt7Yb1Nc5Hd4Jm6Pa0Se"  # random-looking; the key name is irrelevant
    assert [f.rule_id for f in run(f"REST={blob}")] == ["env-secret"]
    assert [f.rule_id for f in run(f"export REST = {blob}")] == ["env-secret"]


def test_env_rule_ignores_ordinary_assignments():
    sha = "a3f5c9e1b27d4086f1e2c3d4b5a69788c9d0e1f2"
    for line in ("PORT=8080", "NAME=aaaaaaaaaaaaaaaaaaaaaaaa", f"COMMIT={sha}", "DEBUG=true"):
        assert run(line) == [], line


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


def test_finding_carries_confidence_match_and_suggestion(aws_key):
    [f] = run(f"KEY = '{aws_key}'")
    assert f.confidence == "high"
    assert f.context == "KEY = 'AKIA…90'"  # the line, with the secret masked
    assert "IAM" in f.suggestion


def test_context_masks_every_secret_on_the_line(aws_key, gh_token):
    findings = run(f"a={aws_key} b={gh_token}")
    assert len(findings) == 2
    for f in findings:
        assert aws_key not in f.context and gh_token not in f.context


def test_confidence_drops_one_level_in_tests_and_docs(aws_key):
    def conf(path):
        return next(scan_chunk(Chunk(aws_key, path, 1))).confidence

    assert conf("src/app.py") == "high"
    assert conf("tests/test_app.py") == "medium"
    assert conf("docs/setup.md") == "medium"
    assert conf("src/test_helpers.py") == "medium"


def test_rule_confidence_levels():
    [env] = run("REST=Zk9xQ2v8Lw3Rt7Yb1Nc5Hd4Jm6Pa0Se")
    [generic] = run('password = "correct-horse-battery"')
    assert (env.confidence, generic.confidence) == ("medium", "low")


def test_history_suggestion_says_deleting_is_not_enough(aws_key):
    [f] = scan_chunk(Chunk(aws_key, "f.py", 1, "67632ec2abcdef"))
    assert "67632ec2" in f.suggestion and "not enough" in f.suggestion


def test_long_lines_are_trimmed_around_the_match(aws_key):
    [f] = run("x = 1; " * 40 + aws_key + " # " + "y" * 200)
    assert "AKIA…90" in f.context and len(f.context) <= 102
