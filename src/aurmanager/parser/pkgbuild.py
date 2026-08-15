from __future__ import annotations

import re
from pathlib import Path

from ..model import RuleContext
from .bash_ast import build_module_scope, extract_functions, mask_function_bodies, parse_script

_SCALAR_RE = re.compile(
    r'^\s*(pkgname|pkgver|pkgrel|pkgbase)=(["\']?)(.*?)\2\s*$', re.MULTILINE
)

CHECKSUM_KEYS = (
    "cksums",
    "md5sums",
    "sha1sums",
    "sha224sums",
    "sha256sums",
    "sha384sums",
    "sha512sums",
    "b2sums",
)


def parse_pkgbuild(path: Path) -> RuleContext:
    source = path.read_text(errors="replace")
    parsed = parse_script(source)

    scalars: dict[str, str] = {}
    for m in _SCALAR_RE.finditer(source):
        key, _, value = m.group(1), m.group(2), m.group(3)
        scalars.setdefault(key, value)

    # Split packages declare pkgname=('a' 'b') as an array; a single pkgname=foo
    # scalar is only meaningful when there's no array form. Checking the array
    # first also sidesteps a quirk of _SCALAR_RE: against `pkgname=(...)`  it still
    # matches (the empty quote-group case), capturing the literal text "(...)"  as
    # if it were a scalar value, which would be wrong for split packages.
    array_names = parsed.arrays.get("pkgname")
    pkgname = array_names[0] if array_names else scalars.get("pkgname")

    checksums = {k: v for k, v in parsed.arrays.items() if k in CHECKSUM_KEYS}
    functions = extract_functions(parsed.ast_nodes)
    module_scope = build_module_scope(parsed.ast_nodes, source)
    module_scope_source = mask_function_bodies(parsed.ast_nodes, source)

    return RuleContext(
        file=path,
        source=source,
        ast=parsed.ast_nodes,
        parse_error=parsed.parse_error,
        pkgname=pkgname,
        pkgver=scalars.get("pkgver"),
        sources=parsed.arrays.get("source", []),
        checksums=checksums,
        functions=functions,
        module_scope=module_scope,
        module_scope_source=module_scope_source,
    )
