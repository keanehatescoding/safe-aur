from __future__ import annotations

from aurmanager.rules.integrity import INT005InstallHookPullsUnpinnedDeps


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
