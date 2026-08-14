from __future__ import annotations

from aurmanager.rules.persistence import (
    PER001ShellRcWrite,
    PER002CronPersistence,
    PER003SystemdEnableAtBuildTime,
    PER004AutostartWrite,
    PER005AuthorizedKeysAppend,
    PER006DisguisedBinaryDrop,
)


def test_per001_fires_on_bashrc_append(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          echo "export FOO=bar" >> ~/.bashrc
        }
        """
    )
    assert len(list(PER001ShellRcWrite().check(ctx))) == 1


def test_per002_fires_on_crontab_install_from_file(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          crontab /tmp/job.cron
        }
        """
    )
    assert len(list(PER002CronPersistence().check(ctx))) == 1


def test_per002_does_not_fire_on_crontab_list_or_remove(make_pkgbuild_ctx):
    # crontab -l (list) and crontab -r (remove) are read-only/destructive, not
    # installing anything -- neither should be flagged as persistence.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          crontab -l
          crontab -r
        }
        """
    )
    assert list(PER002CronPersistence().check(ctx)) == []


def test_per003_fires_on_systemctl_enable(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        package() {
          systemctl enable myservice.service
        }
        """
    )
    assert len(list(PER003SystemdEnableAtBuildTime().check(ctx))) == 1


def test_per003_does_not_fire_on_shipping_unit_file(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        package() {
          install -Dm644 myservice.service "$pkgdir/usr/lib/systemd/system/myservice.service"
        }
        """
    )
    assert list(PER003SystemdEnableAtBuildTime().check(ctx)) == []


def test_per004_fires_on_autostart_copy(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cp x.desktop ~/.config/autostart/x.desktop
        }
        """
    )
    assert len(list(PER004AutostartWrite().check(ctx))) == 1


def test_per005_fires_on_authorized_keys_append(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys
        }
        """
    )
    assert len(list(PER005AuthorizedKeysAppend().check(ctx))) == 1


def test_per006_fires_on_disguised_tmp_binary(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cp payload /tmp/systemd-initd
        }
        """
    )
    assert len(list(PER006DisguisedBinaryDrop().check(ctx))) == 1


def test_per006_does_not_fire_on_normal_tmp_use(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cp payload /tmp/build-scratch
        }
        """
    )
    assert list(PER006DisguisedBinaryDrop().check(ctx)) == []
