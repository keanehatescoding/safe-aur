from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import (
    DOWNLOADERS,
    command_words,
    describe_scope,
    download_output_targets,
    iter_scopes,
    line_of,
    walk,
)
from ..regex_fallback import find_line_matches
from .base import Rule

_SHELL_RC_RE = re.compile(
    r"(?:>>|>)\s*['\"]?~?/?(?:\.bashrc|\.bash_profile|\.profile|\.zshrc)\b"
    r"|tee\s+(?:-a\s+)?['\"]?~?/?(?:\.bashrc|\.bash_profile|\.profile|\.zshrc)\b"
)
_CRON_RE = re.compile(r"\bcrontab\s+(?!-[lr]\b)\S+|/etc/cron\.\w+/|~/\.config/cron\b")
_SYSTEMCTL_RE = re.compile(r"\bsystemctl\s+(?:enable|start|--now)\b")
_AUTOSTART_RE = re.compile(
    r"(?:>>|>|tee\s+(?:-a\s+)?)\s*['\"]?~?/\.config/autostart/"
    r"|\b(?:cp|mv|install)\b[^\n]*~?/\.config/autostart/"
)
_AUTHORIZED_KEYS_RE = re.compile(
    r"(?:>>|>|tee\s+(?:-a\s+)?)\s*['\"]?~?/\.ssh/authorized_keys\b"
)
# Real kernel-thread names routinely include an internal slash (per-CPU instances
# like kworker/0:3, [kworker/u8:1]) -- so a plain rsplit("/")-based "basename"
# extraction would chop the name at the wrong point. Instead, match the disguised
# name anchored to the end of the path, preceded by either the start of the
# remainder or a directory separator; this handles both bare and bracketed forms,
# and arbitrary subdirectories under /tmp, without needing to isolate a basename.
_TMP_ROOT_RE = re.compile(r"^/(?:tmp|var/tmp)/")
_DISGUISED_NAME_RE = re.compile(
    r"(?:^|/)(?:systemd-[a-z]+|kworker(?:/\S*)?|\[[a-z0-9_:/]+\])$", re.IGNORECASE
)


def _disguised_tmp_target(path: str) -> bool:
    if not _TMP_ROOT_RE.match(path):
        return False
    return bool(_DISGUISED_NAME_RE.search(path))


def _findings_for(rule: Rule, ctx: RuleContext, pattern, message: str, remediation: str) -> list[Finding]:
    return [
        Finding(
            rule_id=rule.rule_id,
            severity=rule.default_severity,
            message=message,
            file=ctx.file,
            line=line_no,
            snippet=line_text,
            incident_ref=rule.incident_refs[0] if rule.incident_refs else None,
            remediation=remediation,
        )
        for line_no, line_text, _ in find_line_matches(ctx.source, pattern)
    ]


class PER001ShellRcWrite(Rule):
    """Writing to a user's shell startup file (~/.bashrc, ~/.profile, ...) makes a
    payload survive across sessions without needing root -- classic persistence."""

    rule_id = "PER001"
    category = "persistence"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return _findings_for(
            self,
            ctx,
            _SHELL_RC_RE,
            "Writes to a shell startup file, which persists a payload across every new shell session.",
            "Never modify a user's shell rc files from a build/install script.",
        )


class PER002CronPersistence(Rule):
    """Cron entries re-run a payload on a schedule without needing an active login
    session -- another common persistence mechanism."""

    rule_id = "PER002"
    category = "persistence"
    default_severity = Severity.HIGH

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return _findings_for(
            self,
            ctx,
            _CRON_RE,
            "Installs or modifies a crontab/cron.d entry, which persists a payload on a schedule.",
            "A package should never install cron jobs as a side effect of build/install.",
        )


class PER003SystemdEnableAtBuildTime(Rule):
    """A build or install script should never enable/start a systemd unit itself
    (that's what pacman hooks and unit presets are for) -- the acroread 2018 payload
    used exactly this to reconfigure systemd for periodic re-execution. See
    tests/fixtures/incidents/2018_acroread_curl_pipe_bash/SOURCE.md."""

    rule_id = "PER003"
    category = "persistence"
    default_severity = Severity.HIGH
    incident_refs = ("AUR-2018-acroread",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return _findings_for(
            self,
            ctx,
            _SYSTEMCTL_RE,
            "Enables/starts a systemd unit directly from a build or install script -- units should be shipped for the package manager to install, not enabled as a side effect.",
            "Ship the unit file under $pkgdir and let the user/pacman hooks enable it, if at all.",
        )


class PER004AutostartWrite(Rule):
    """Desktop autostart entries run a payload every time the user logs into a
    graphical session."""

    rule_id = "PER004"
    category = "persistence"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return _findings_for(
            self,
            ctx,
            _AUTOSTART_RE,
            "Writes to ~/.config/autostart/, which runs a payload on every graphical login.",
            "A package should not write to a user's autostart directory outside of $pkgdir packaging.",
        )


class PER005AuthorizedKeysAppend(Rule):
    """Appending to ~/.ssh/authorized_keys grants persistent remote access -- one of
    the most severe persistence mechanisms possible."""

    rule_id = "PER005"
    category = "persistence"
    default_severity = Severity.CRITICAL

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        return _findings_for(
            self,
            ctx,
            _AUTHORIZED_KEYS_RE,
            "Appends to ~/.ssh/authorized_keys, granting persistent remote SSH access.",
            "A package must never modify authorized_keys.",
        )


class PER006DisguisedBinaryDrop(Rule):
    """Dropping a binary into /tmp or /var/tmp under a name designed to look like a
    system process (systemd-*, kworker*, a bracketed kernel-thread-style name) is a
    disguise technique used by the 2025 Chaos RAT AUR packages (systemd-initd) and
    the 2026 Atomic Arch rootkit (kernel-thread name spoofing)."""

    rule_id = "PER006"
    category = "persistence"
    default_severity = Severity.HIGH
    incident_refs = ("AUR-2025-chaos-rat", "AUR-2026-atomic-arch")

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in iter_scopes(ctx):
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                words = command_words(node)
                if not words:
                    continue
                name = words[0]
                if name in DOWNLOADERS:
                    targets = download_output_targets(name, words)
                elif name in ("cp", "mv"):
                    # destination is the last non-flag argument
                    args = [w for w in words[1:] if not w.startswith("-")]
                    targets = [args[-1]] if args else []
                else:
                    continue

                for target in targets:
                    if not _disguised_tmp_target(target):
                        continue
                    line = line_of(node.pos[0], ctx.source)
                    snippet = ctx.source.splitlines()[line - 1].strip() if line else None
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            message=(
                                f"{describe_scope(fn_name)} drops a binary at '{target}', a "
                                f"name disguised to look like a system process."
                            ),
                            file=ctx.file,
                            line=line,
                            snippet=snippet,
                            incident_ref=self.incident_refs[0],
                            remediation=(
                                "Legitimate packages install binaries under $pkgdir, not /tmp, "
                                "and never under a spoofed system-process name."
                            ),
                        )
                    )
        return findings
