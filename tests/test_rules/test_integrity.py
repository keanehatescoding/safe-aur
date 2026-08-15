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
