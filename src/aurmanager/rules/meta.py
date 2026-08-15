from __future__ import annotations

from typing import Iterable

from ..model import Finding, RuleContext, Severity
from .base import Rule


class META001UnparseableInput(Rule):
    """If bashlex fails to parse a file (even after array-literal masking), every
    AST-based rule silently sees an empty function/module-scope set and finds
    nothing -- a malformed or deliberately parser-breaking PKGBUILD would otherwise
    scan as completely clean instead of as a degraded, incomplete scan. This rule
    makes that failure visible instead of silent."""

    rule_id = "META001"
    category = "meta"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        if not ctx.parse_error:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message=(
                    f"{ctx.file.name} could not be fully parsed ({ctx.parse_error}) -- "
                    f"AST-based rules could not inspect its function bodies, so this scan "
                    f"is incomplete. Do not treat a clean result as a clean file."
                ),
                file=ctx.file,
                line=None,
                snippet=None,
                remediation=(
                    "Review this file manually; the scanner cannot vouch for content it "
                    "could not parse. If this is a false positive against a legitimate "
                    "bash construct, please report it."
                ),
            )
        ]
