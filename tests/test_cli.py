import json
import os
import stat

from conftest import git

from secretscan.cli import main


def test_clean_tree_exits_zero(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    assert main(["scan", str(tmp_path)]) == 0
    assert "No secrets found" in capsys.readouterr().out


def test_finding_exits_one_and_redacts(tmp_path, capsys, aws_key):
    (tmp_path / "cfg.py").write_text(f"KEY = '{aws_key}'\n")
    assert main(["scan", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "cfg.py:1" in out and "aws-access-key-id" in out
    assert aws_key not in out


def test_history_scan_catches_removed_secret(repo, capsys, aws_key):
    f = repo / "cfg.py"
    f.write_text(f"KEY = '{aws_key}'\n")
    git(repo, "add", "."), git(repo, "commit", "-qm", "oops")
    f.write_text("KEY = None\n")
    git(repo, "commit", "-qam", "fix")
    assert main(["scan", str(repo)]) == 0  # working tree is clean...
    assert main(["scan", str(repo), "--history"]) == 1  # ...history is not
    assert "commit " in capsys.readouterr().out


def test_baseline_roundtrip_hides_old_but_not_new(tmp_path, aws_key, gh_token):
    (tmp_path / "a.py").write_text(f"K='{aws_key}'\n")
    base = tmp_path.parent / (tmp_path.name + "-base.json")
    assert main(["scan", str(tmp_path), "--write-baseline", str(base)]) == 0
    assert main(["scan", str(tmp_path), "--baseline", str(base)]) == 0
    (tmp_path / "a.py").write_text(f"# moved down\nK='{aws_key}'\n")  # line shift: still baselined
    assert main(["scan", str(tmp_path), "--baseline", str(base)]) == 0
    (tmp_path / "b.py").write_text(f"T='{gh_token}'\n")
    assert main(["scan", str(tmp_path), "--baseline", str(base)]) == 1


def test_allowlist_config(tmp_path, aws_key):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "k.py").write_text(f"K='{aws_key}'\n")
    (tmp_path / ".secretscan.toml").write_text('[allowlist]\npaths = ["fixtures/*"]\n')
    assert main(["scan", str(tmp_path)]) == 0


def test_sarif_output_shape_and_no_raw_secret(tmp_path, aws_key):
    (tmp_path / "a.py").write_text(f"K='{aws_key}'\n")
    out = tmp_path.parent / (tmp_path.name + ".sarif")
    assert main(["scan", str(tmp_path), "--format", "sarif", "--output", str(out)]) == 1
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    [result] = doc["runs"][0]["results"]
    assert result["ruleId"] == "aws-access-key-id"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert aws_key not in out.read_text()


def test_bad_baseline_path_is_an_error(tmp_path):
    assert main(["scan", str(tmp_path), "--baseline", str(tmp_path / "nope.json")]) == 2


def test_not_a_git_repo_is_an_error(tmp_path):
    assert main(["scan", str(tmp_path), "--staged"]) == 2


def test_install_hook_and_precommit_blocks_secret(repo, aws_key):
    assert main(["install-hook", str(repo)]) == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.stat().st_mode & stat.S_IXUSR
    assert main(["install-hook", str(repo)]) == 2  # refuses to overwrite
    assert main(["install-hook", str(repo), "--force"]) == 0
    (repo / "a.py").write_text(f"K='{aws_key}'\n")
    git(repo, "add", "a.py")
    prev = os.getcwd()
    os.chdir(repo)  # hook runs `secretscan scan --staged` in the repo
    try:
        assert main(["scan", "--staged"]) == 1
    finally:
        os.chdir(prev)
