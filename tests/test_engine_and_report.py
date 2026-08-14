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
