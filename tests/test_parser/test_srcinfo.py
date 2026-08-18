from __future__ import annotations

from aurmanager.parser.srcinfo import parse_srcinfo_fields


def _write(tmp_path, body):
    p = tmp_path / ".SRCINFO"
    p.write_text(body)
    return p


def test_parse_srcinfo_fields_basic(tmp_path):
    path = _write(
        tmp_path,
        """pkgbase = foo
\tpkgver = 1.0
\tpkgrel = 1
\tarch = x86_64
\tarch = aarch64
\tsource = foo-1.0.tar.gz::https://example.com/foo/1.0.tar.gz
\tsha256sums = deadbeef

pkgname = foo
""",
    )
    fields = parse_srcinfo_fields(path)
    assert fields["arch"] == ["x86_64", "aarch64"]
    assert fields["source"] == ["foo-1.0.tar.gz::https://example.com/foo/1.0.tar.gz"]
    assert fields["sha256sums"] == ["deadbeef"]


def test_parse_srcinfo_fields_stops_at_first_pkgname_block(tmp_path):
    # Per-subpackage overrides in a pkgname = block are out of scope -- only
    # pkgbase-level source/checksum arrays are read.
    path = _write(
        tmp_path,
        """pkgbase = foo
\tpkgver = 1.0
\tsource = foo-1.0.tar.gz::https://example.com/foo.tar.gz
\tsha256sums = deadbeef

pkgname = foo
\tdepends = bar

pkgname = foo-doc
\tdepends = baz
""",
    )
    fields = parse_srcinfo_fields(path)
    assert "depends" not in fields
    assert fields["source"] == ["foo-1.0.tar.gz::https://example.com/foo.tar.gz"]
