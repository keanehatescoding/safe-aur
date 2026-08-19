from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..regex_fallback import find_line_matches
from .base import Rule

# Same shape as RCE001 (curl/wget piped into an interpreter), but as plain
# text: patches modify arbitrary file types (C source, Makefiles, config
# files, shell scripts...), not just bash, so there's no AST to walk here the
# way RCE001 does for a real PKGBUILD/.install. Deliberately not anchored to
# a specific interpreter list beyond the common ones -- a patch adding this
# exact shape to *any* file it touches is inherently suspicious; legitimate
# one-line bugfix patches don't introduce a network-fetch-then-execute
# pipeline.
_PATCH_PIPED_EXEC_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|perl)\b"
)


class PAT001PipedExecAddedByPatch(Rule):
    """A .patch/.diff file (referenced from a PKGBUILD's source=() and applied
    during prepare()) that *adds* a curl/wget-piped-into-a-shell line is
    injecting the same remote-code-execution shape RCE001 detects in a
    PKGBUILD's own build()/package() -- just hidden inside a file the patch
    modifies instead. A reviewer skimming the PKGBUILD sees nothing
    suspicious; the payload only appears once the patch is actually applied
    to the extracted source tree. Generic heuristic -- no specific AUR
    incident involving a malicious patch file is known (verified via web
    search), but the technique is a direct extension of the 2018 acroread
    curl-pipe-bash mechanism RCE001 is grounded in.

    Only runs against patch-derived contexts (ctx.is_patch) -- the identical
    construct in a real PKGBUILD/.install is already caught more precisely by
    RCE001's AST-based check, and running both would double-report it."""

    rule_id = "PAT001"
    category = "rce"
    default_severity = Severity.CRITICAL

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        if not ctx.is_patch:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.default_severity,
                message=(
                    "This patch adds a line piping curl/wget output directly into a "
                    "shell -- applying it injects remote-code-execution into whatever "
                    "file it patches, invisible to anyone reviewing only the PKGBUILD."
                ),
                file=ctx.file,
                line=line_no,
                snippet=line_text,
                remediation=(
                    "Treat any patch adding a network-fetch-then-execute line as "
                    "malicious; review every hunk of every applied patch, not just "
                    "the PKGBUILD."
                ),
            )
            for line_no, line_text, _ in find_line_matches(ctx.source, _PATCH_PIPED_EXEC_RE)
        ]
