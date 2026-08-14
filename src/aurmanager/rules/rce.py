from __future__ import annotations

from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, line_of, walk
from .base import Rule

_DOWNLOADERS = {"curl", "wget"}
_INTERPRETERS = {"bash", "sh", "zsh", "dash", "python", "python3", "perl", "source", "."}


class RCE001CurlPipeBash(Rule):
    """Piping curl/wget output directly into a shell/interpreter executes remote
    content sight-unseen at build or install time -- the exact mechanism used in the
    2018 acroread AUR package hijack, where a curl-piped install payload added
    persistence and exfiltrated system info. See tests/fixtures/incidents/
    2018_acroread_curl_pipe_bash/SOURCE.md."""

    rule_id = "RCE001"
    category = "rce"
    default_severity = Severity.CRITICAL
    incident_refs = ("AUR-2018-acroread",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in ctx.functions.items():
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "pipeline":
                    continue
                commands = [p for p in node.parts if getattr(p, "kind", None) == "command"]
                if len(commands) < 2:
                    continue
                first_name = command_name(commands[0])
                last_name = command_name(commands[-1])
                if first_name in _DOWNLOADERS and last_name in _INTERPRETERS:
                    line = line_of(node.pos[0], ctx.source)
                    snippet = ctx.source.splitlines()[line - 1].strip() if line else None
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            message=(
                                f"'{fn_name}()' pipes the output of '{first_name}' directly "
                                f"into '{last_name}', executing remote content without any "
                                f"integrity check or human review."
                            ),
                            file=ctx.file,
                            line=line,
                            snippet=snippet,
                            incident_ref=self.incident_refs[0],
                            remediation=(
                                "Never pipe curl/wget output directly into a shell. Download "
                                "to a file, verify its checksum/signature, and review its "
                                "contents before executing anything."
                            ),
                        )
                    )
        return findings
