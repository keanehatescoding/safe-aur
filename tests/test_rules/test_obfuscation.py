from __future__ import annotations

from aurmanager.rules.obfuscation import (
    OBF001Base64DecodeExec,
    OBF002EvalUsage,
    OBF003HexEscapePayload,
    OBF004Rot13DecodeExec,
)


def test_obf001_fires_on_base64_decode_pipe_bash(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          echo 'ZWNobyBoaWRkZW4tcGF5bG9hZC1oZXJl' | base64 -d | bash
        }
        """
    )
    findings = list(OBF001Base64DecodeExec().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


def test_obf001_does_not_fire_on_plain_base64_decode(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          base64 -d config.b64 > config.txt
        }
        """
    )
    assert list(OBF001Base64DecodeExec().check(ctx)) == []


def test_obf002_fires_on_eval(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          eval "$cmd"
        }
        """
    )
    findings = list(OBF002EvalUsage().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_obf003_fires_on_hex_escape_run(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        r"""
        build() {
          echo -e "\x63\x75\x72\x6c\x20\x2d\x73\x20\x68\x74\x74\x70"
        }
        """
    )
    findings = list(OBF003HexEscapePayload().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "MEDIUM"


def test_obf004_fires_on_rot13_pipe_bash(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        build() {
          echo 'uryyb' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash
        }
        """
    )
    findings = list(OBF004Rot13DecodeExec().check(ctx))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"
