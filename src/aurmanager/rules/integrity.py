from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, command_words, line_of, walk
from .base import Rule

_PACKAGE_MANAGERS = {"npm", "pip", "pip3", "go", "bun", "yarn", "pnpm"}
_INSTALL_VERBS = {"install", "add", "get"}
_INSTALL_HOOKS = ("post_install", "post_upgrade")

# pip's `==1.2.3`, npm/go's `@1.2.3` or `@v1.2.3` -- deliberately excludes npm/go
# "pins" like `@latest`/`@next` that aren't actually pinned to a fixed version.
_VERSION_PIN_RE = re.compile(r"(==\S|@=?v?\d)")


class INT005InstallHookPullsUnpinnedDeps(Rule):
    """A post_install/post_upgrade hook silently running a package manager to pull
    down more code at install time bypasses the AUR review process entirely for
    whatever that dependency turns out to be -- exactly how the 2026 Atomic Arch
    campaign's `.install` hooks pulled the malicious `atomic-lockfile`/`js-digest`
    npm packages that dropped the actual infostealer/rootkit payload. See
    tests/fixtures/incidents/2026_atomic_arch_install_hook_and_obfuscation/
    SOURCE.md."""

    rule_id = "INT005"
    category = "integrity"
    default_severity = Severity.HIGH
    incident_refs = ("AUR-2026-atomic-arch",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in ctx.functions.items():
            if fn_name not in _INSTALL_HOOKS:
                continue
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                name = command_name(node)
                if name not in _PACKAGE_MANAGERS:
                    continue
                words = command_words(node)
                if len(words) < 2 or words[1] not in _INSTALL_VERBS:
                    continue

                specs = [w for w in words[2:] if not w.startswith("-")]
                all_pinned = bool(specs) and all(_VERSION_PIN_RE.search(s) for s in specs)

                line = line_of(node.pos[0], ctx.source)
                snippet = ctx.source.splitlines()[line - 1].strip() if line else None
                if all_pinned:
                    detail = "pins a specific version, but still fetches unaudited third-party code"
                else:
                    detail = "pulls additional, unpinned code"
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        message=(
                            f"'{fn_name}()' runs '{name} {words[1]}' to {detail} at install "
                            f"time -- this bypasses AUR review for whatever that dependency "
                            f"resolves to."
                        ),
                        file=ctx.file,
                        line=line,
                        snippet=snippet,
                        incident_ref=self.incident_refs[0],
                        remediation=(
                            "Package the actual runtime dependency properly (depends=()) "
                            "instead of fetching it via a package manager at install time."
                        ),
                    )
                )
        return findings
