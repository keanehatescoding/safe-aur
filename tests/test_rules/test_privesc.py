from __future__ import annotations

from aurmanager.rules.privesc import PRV001SudoInBuildLifecycle, PRV002SudoersEdit, PRV003SetuidBit


def test_prv001_fires_on_sudo_in_build(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          sudo ./validator --install
        }
        """
    )
    findings = list(PRV001SudoInBuildLifecycle().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_prv001_does_not_fire_outside_build_lifecycle_functions(make_install_ctx):
    # sudo inside a .install hook isn't covered by PRV001 -- pacman itself already
    # runs .install hooks as root, so "sudo" there isn't the same anomaly it is
    # inside makepkg's unprivileged build()/package().
    ctx = make_install_ctx(
        """
        post_install() {
          sudo systemctl daemon-reload
        }
        """
    )
    assert list(PRV001SudoInBuildLifecycle().check(ctx)) == []


def test_prv002_fires_on_sudoers_edit(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/backdoor
        }
        """
    )
    assert len(list(PRV002SudoersEdit().check(ctx))) == 1


def test_prv002_fires_on_bare_visudo(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          visudo
        }
        """
    )
    assert len(list(PRV002SudoersEdit().check(ctx))) == 1


def test_prv002_does_not_fire_on_visudo_check_modes(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          visudo -c
          visudo --check
        }
        """
    )
    assert list(PRV002SudoersEdit().check(ctx)) == []


def test_prv003_fires_on_setuid_chmod(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        package() {
          chmod u+s "$pkgdir/usr/bin/foo"
        }
        """
    )
    assert len(list(PRV003SetuidBit().check(ctx))) == 1


def test_prv003_fires_on_chmod_with_long_option(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        package() {
          chmod --recursive u+s "$pkgdir/usr/bin/"
        }
        """
    )
    assert len(list(PRV003SetuidBit().check(ctx))) == 1


def test_prv003_does_not_fire_on_normal_chmod(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        package() {
          chmod 755 "$pkgdir/usr/bin/foo"
        }
        """
    )
    assert list(PRV003SetuidBit().check(ctx)) == []
