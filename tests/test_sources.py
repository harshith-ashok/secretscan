"""
The most valuable one builds a real temporary git repo, commits a line,
deletes it, and asserts history still contains it, 
which is the whole reason the history mode exists.
"""
from conftest import git

from secretscan.sources import iter_history, iter_staged, iter_worktree, parse_diff

DIFF = """\
commit:abc123
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -1,0 +2,2 @@
+first
+++not a header
@@ -9 +12 @@
-old
+second
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""


def test_parse_diff_tracks_paths_lines_and_commit():
    got = [(c.path, c.line, c.text, c.commit) for c in parse_diff(DIFF.splitlines())]
    assert got == [
        ("app.py", 2, "first", "abc123"),
        ("app.py", 3, "++not a header", "abc123"),  # '+++' inside a hunk is content
        ("app.py", 12, "second", "abc123"),
    ]


def test_worktree_skips_binary_git_and_big_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello\nworld\n")
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01secret")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("ignored")
    (tmp_path / "big.txt").write_text("x" * 200)
    chunks = list(iter_worktree(tmp_path, max_bytes=100))
    assert [(c.path, c.line, c.text) for c in chunks] == [
        ("a.txt", 1, "hello"),
        ("a.txt", 2, "world"),
    ]


def test_staged_only_sees_staged_additions(repo):
    (repo / "a.txt").write_text("one\ntwo\n")
    git(repo, "add", "a.txt")
    (repo / "b.txt").write_text("unstaged\n")
    assert [(c.path, c.line, c.text) for c in iter_staged(repo)] == [
        ("a.txt", 1, "one"), ("a.txt", 2, "two"),
    ]  # fmt: skip


def test_history_finds_lines_that_were_later_deleted(repo):
    f = repo / "cfg.txt"
    f.write_text("token_line\n")
    git(repo, "add", "."), git(repo, "commit", "-qm", "add")
    f.write_text("clean\n")
    git(repo, "commit", "-qam", "remove")
    texts = [c.text for c in iter_history(repo)]
    assert "token_line" in texts  # gone from HEAD, still in history
    assert "clean" in texts