from __future__ import annotations

from pathlib import Path

from ..model import RuleContext
from .bash_ast import extract_functions, parse_script

HOOK_NAMES = (
    "pre_install",
    "post_install",
    "pre_upgrade",
    "post_upgrade",
    "pre_remove",
    "post_remove",
)


def parse_install_script(path: Path) -> RuleContext:
    source = path.read_text(errors="replace")
    parsed = parse_script(source)
    functions = extract_functions(parsed.ast_nodes, HOOK_NAMES)

    return RuleContext(
        file=path,
        source=source,
        ast=parsed.ast_nodes,
        parse_error=parsed.parse_error,
        functions=functions,
    )
