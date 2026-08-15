from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, describe_scope, iter_scopes, walk
from ..regex_fallback import find_line_matches
from .base import Rule

# echo '<base64 blob>' | base64 -d | bash -- the exact one-liner shape reported in
# the 2026 Atomic Arch campaign's obfuscated samples.
_OBF001_RE = re.compile(
    r"echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+(?:-d|--decode)\b"
    r"[^\n]*\|\s*(?:bash|sh|zsh|dash|eval)\b"
)

# 6+ consecutive \xHH hex escapes in command position -- bashlex treats these as
# opaque word text (documented parameter-expansion limitation), so this has to be a
# textual check.
_OBF003_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")

_OBF004_RE = re.compile(
    r"\b(?:rot13|tr\s+['\"]?A-Za-z['\"]?\s+['\"]?N-ZA-Mn-za-m['\"]?)\b"
    r"[^\n]*\|\s*(?:bash|sh|zsh|dash|eval)\b"
)


class OBF001Base64DecodeExec(Rule):
    """A base64 blob decoded and piped straight into a shell hides the actual payload
    from anyone reading the PKGBUILD. This exact `echo '...' | base64 -d | bash`
    shape was reported in obfuscated samples from the 2026 Atomic Arch AUR campaign."""

    rule_id = "OBF001"
    category = "obfuscation"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2026-atomic-arch",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="Base64-encoded content is decoded and piped directly into a shell, hiding the actual payload from review.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                incident_ref=self.incident_refs[0],
                remediation="Decode and review the payload yourself; never execute decoded content sight-unseen.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _OBF001_RE)
        ]


class OBF002EvalUsage(Rule):
    """`eval` executes a dynamically-constructed string, which defeats static review
    by design -- whatever it actually runs isn't visible in the source text."""

    rule_id = "OBF002"
    category = "obfuscation"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in iter_scopes(ctx):
            for node in walk(fn_node):
                if getattr(node, "kind", None) == "command" and command_name(node) == "eval":
                    line = ctx.source.count("\n", 0, node.pos[0]) + 1
                    snippet = ctx.source.splitlines()[line - 1].strip() if line else None
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            message=f"{describe_scope(fn_name)} uses eval, which hides the actual command being run from static review.",
                            file=ctx.file,
                            line=line,
                            snippet=snippet,
                            remediation="Avoid eval; write out the command being run explicitly.",
                        )
                    )
        return findings


class OBF003HexEscapePayload(Rule):
    """A long run of \\xHH hex escapes in command position is a common way to hide a
    command name/argument from a quick source read (and from naive AST-only
    scanners, since bashlex treats these as opaque text). Reported in obfuscated
    samples from the 2026 Atomic Arch campaign."""

    rule_id = "OBF003"
    category = "obfuscation"
    default_severity = Severity.MEDIUM
    incident_refs = ("AUR-2026-atomic-arch",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="A long run of hex-escaped characters appears in command position, likely hiding a command from casual review.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                incident_ref=self.incident_refs[0],
                remediation="Avoid hex-escaped command strings; write commands out in plain text.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _OBF003_RE)
        ]


class OBF004Rot13DecodeExec(Rule):
    """rot13 (or an equivalent `tr` transliteration) decoding content that is then
    piped into a shell -- a lightweight obfuscation layer with the same intent as
    OBF001's base64 variant."""

    rule_id = "OBF004"
    category = "obfuscation"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="Content is rot13-decoded and piped directly into a shell, hiding the actual payload from review.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                remediation="Decode and review the payload yourself; never execute decoded content sight-unseen.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _OBF004_RE)
        ]
