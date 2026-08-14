from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, command_words, line_of, walk
from ..regex_fallback import find_line_matches
from .base import Rule

_ELEVATION_COMMANDS = {"sudo", "doas", "pkexec"}
_BUILD_LIFECYCLE_FUNCTIONS = ("prepare", "build", "check", "package", "pkgver")

_SUDOERS_EDIT_RE = re.compile(
    r"(?:>>|>|tee\s+(?:-a\s+)?)\s*['\"]?/etc/sudoers(?:\.d/\S+)?\b|\bvisudo\b"
)
_SETUID_CHMOD_RE = re.compile(r"\bchmod\s+(?:u\+s|g\+s|[24]\d{3}|[24]\d{2})\b")


class PRV001SudoInBuildLifecycle(Rule):
    """makepkg runs prepare()/build()/check()/package() as an unprivileged user by
    design -- any of them needing sudo/doas/pkexec is a direct sign something in the
    build path is trying to escalate privileges. This is the exact pattern from the
    2026 openconnect-sso incident: a `validator` binary added to source=() and
    invoked via sudo inside the build path. See tests/fixtures/incidents/
    2026_openconnect_sso_sudo_privesc/SOURCE.md."""

    rule_id = "PRV001"
    category = "privesc"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2026-openconnect-sso",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in ctx.functions.items():
            if fn_name not in _BUILD_LIFECYCLE_FUNCTIONS:
                continue
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                name = command_name(node)
                if name in _ELEVATION_COMMANDS:
                    words = command_words(node)
                    line = line_of(node.pos[0], ctx.source)
                    snippet = ctx.source.splitlines()[line - 1].strip() if line else None
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            message=(
                                f"'{fn_name}()' invokes '{name}'"
                                + (f" ({' '.join(words[1:3])}...)" if len(words) > 1 else "")
                                + f" -- {fn_name}() runs as the unprivileged build user under "
                                f"makepkg and should never need root."
                            ),
                            file=ctx.file,
                            line=line,
                            snippet=snippet,
                            incident_ref=self.incident_refs[0],
                            remediation=(
                                "Remove the privilege escalation. If a build genuinely needs a "
                                "privileged step, that belongs in a post-install hook the user "
                                "explicitly reviews, not silently inside build()/package()."
                            ),
                        )
                    )
        return findings


class PRV002SudoersEdit(Rule):
    """Direct edits to /etc/sudoers or /etc/sudoers.d grant persistent, unreviewable
    privilege escalation."""

    rule_id = "PRV002"
    category = "privesc"
    default_severity = Severity.CRITICAL

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="Edits /etc/sudoers (or /etc/sudoers.d), granting persistent privilege escalation.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                remediation="A package must never modify sudoers.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _SUDOERS_EDIT_RE)
        ]


class PRV003SetuidBit(Rule):
    """Setting the setuid/setgid bit on a shipped binary lets any user run it with
    the file owner's (often root's) privileges."""

    rule_id = "PRV003"
    category = "privesc"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="Sets the setuid/setgid bit on a file, letting any user run it with elevated privileges.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                remediation="Avoid setuid/setgid binaries unless there is no alternative, and document why clearly.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _SETUID_CHMOD_RE)
        ]
