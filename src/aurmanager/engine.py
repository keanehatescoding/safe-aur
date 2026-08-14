from __future__ import annotations

from .loader import PackageFiles
from .model import Finding, RuleContext, ScanResult
from .parser.install_script import parse_install_script
from .parser.pkgbuild import parse_pkgbuild
from .rules import ALL_RULES


def scan(files: PackageFiles) -> ScanResult:
    contexts: list[RuleContext] = [parse_pkgbuild(files.pkgbuild)]
    for install_path in files.install_scripts:
        contexts.append(parse_install_script(install_path))

    findings: list[Finding] = []
    for ctx in contexts:
        for rule_cls in ALL_RULES:
            findings.extend(rule_cls().check(ctx))

    return ScanResult(findings=findings)
