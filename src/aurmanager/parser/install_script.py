from __future__ import annotations

from pathlib import Path

from ..model import RuleContext
from .bash_ast import build_module_scope, extract_functions, mask_function_bodies, parse_script


def parse_install_script(path: Path) -> RuleContext:
    source = path.read_text(errors="replace")
    parsed = parse_script(source)
    functions = extract_functions(parsed.ast_nodes)
    module_scope = build_module_scope(parsed.ast_nodes, source)
    module_scope_source = mask_function_bodies(parsed.ast_nodes, source)

    return RuleContext(
        file=path,
        source=source,
        ast=parsed.ast_nodes,
        parse_error=parsed.parse_error,
        functions=functions,
        module_scope=module_scope,
        module_scope_source=module_scope_source,
    )
