from __future__ import annotations

import pytest

from aurmanager.parser.install_script import parse_install_script
from aurmanager.parser.pkgbuild import parse_pkgbuild


@pytest.fixture
def make_pkgbuild_ctx(tmp_path):
    def _make(body: str):
        path = tmp_path / "PKGBUILD"
        path.write_text(body)
        return parse_pkgbuild(path)

    return _make


@pytest.fixture
def make_install_ctx(tmp_path):
    def _make(body: str):
        path = tmp_path / "pkg.install"
        path.write_text(body)
        return parse_install_script(path)

    return _make


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}
