from __future__ import annotations

from aurmanager.diffscan import diff_scan
from aurmanager.report import render_diff_text


def _write(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "PKGBUILD").write_text(body)
    return d


def test_render_diff_text_shows_removed_functions_and_sources(tmp_path):
    # Regression: render_diff_text() only rendered new_functions/new_sources --
    # DiffResult.removed_functions/removed_sources were computed but never shown
    # in the text report.
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz" "https://example.com/extra.patch")
        sha256sums=('deadbeef' 'deadbeef')
        post_install() {
          echo hi
        }
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        """,
    )
    diff = diff_scan(old, new)
    assert diff.removed_functions == ["post_install"]
    assert diff.removed_sources == ["https://example.com/extra.patch"]

    text = render_diff_text(diff, use_color=False)
    assert "Removed function(s): post_install" in text
    assert "Removed source(s): https://example.com/extra.patch" in text


def test_render_diff_text_applies_severity_min_to_resolved_findings(tmp_path):
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('SKIP')
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        """,
    )
    diff = diff_scan(old, new)
    assert [f.rule_id for f in diff.resolved_findings] == ["INT003"]

    from aurmanager.model import Severity

    text = render_diff_text(diff, use_color=False, severity_min=Severity.CRITICAL)
    assert "INT003" not in text
    assert "Findings resolved" not in text
