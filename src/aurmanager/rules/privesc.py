from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, command_words, describe_scope, iter_scopes, line_of, walk
from ..regex_fallback import find_line_matches
from .base import Rule

_ELEVATION_COMMANDS = {"sudo", "doas", "pkexec"}
_BUILD_LIFECYCLE_FUNCTIONS = ("prepare", "build", "check", "package", "pkgver")

_SUDOERS_WRITE_RE = re.compile(r"(?:>>|>|tee\s+(?:-a\s+)?)\s*['\"]?/etc/sudoers(?:\.d/\S+)?\b")
# visudo -c only validates the syntax of the sudoers file and makes no changes;
# only unflagged/modifying invocations are worth reporting.
_VISUDO_MODIFYING_RE = re.compile(r"\bvisudo\b(?![^\n]*\s-c\b)")
_SETUID_CHMOD_RE = re.compile(
    r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:[ugoa]*\+s\b|0?[2-7][0-7]{3}\b)"
)


def _is_build_lifecycle_scope(fn_name: str) -> bool:
    return (
        fn_name in _BUILD_LIFECYCLE_FUNCTIONS
        or fn_name.startswith("package_")
        or fn_name == "<module scope>"
    )


class PRV001SudoInBuildLifecycle(Rule):
    """makepkg runs prepare()/build()/check()/package() (and any package_<pkgname>()
    split-package override) as an unprivileged user by design, and top-level
    PKGBUILD statements run immediately when the file is sourced -- any of them
    needing sudo/doas/pkexec is a direct sign something is trying to escalate
    privileges. This is the exact pattern from the 2026 openconnect-sso incident: a
    `validator` binary added to source=() and invoked via sudo inside the build
    path. See tests/fixtures/incidents/2026_openconnect_sso_sudo_privesc/
    SOURCE.md."""

    rule_id = "PRV001"
    category = "privesc"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2026-openconnect-sso",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in iter_scopes(ctx):
            if not _is_build_lifecycle_scope(fn_name):
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
                                f"{describe_scope(fn_name)} invokes '{name}'"
                                + (f" ({' '.join(words[1:3])}...)" if len(words) > 1 else "")
                                + " -- this runs as the unprivileged build user under makepkg "
                                "and should never need root."
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
    privilege escalation. `visudo -c` (validate only, no changes) is excluded."""

    rule_id = "PRV002"
    category = "privesc"
    default_severity = Severity.CRITICAL

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings = [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="Edits /etc/sudoers (or /etc/sudoers.d), granting persistent privilege escalation.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                remediation="A package must never modify sudoers.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _SUDOERS_WRITE_RE)
        ]
        findings.extend(
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message="Invokes visudo (outside of -c validate-only mode), which edits sudoers.",
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                remediation="A package must never modify sudoers.",
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _VISUDO_MODIFYING_RE)
        )
        return findings


class PRV003SetuidBit(Rule):
    """Setting the setuid/setgid bit on a shipped binary lets any user run it with
    the file owner's (often root's) privileges. Covers symbolic forms (u+s, g+s,
    a+s, ug+s), numeric 4-digit modes with the setuid/setgid bit set (4755, 6755,
    02755, ...), and chmod invocations with flags before the mode (chmod -R u+s)."""

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
