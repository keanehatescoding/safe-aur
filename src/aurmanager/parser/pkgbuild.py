from __future__ import annotations

import re
from pathlib import Path

from ..model import RuleContext
from .bash_ast import extract_functions, parse_script

_SCALAR_RE = re.compile(
    r'^\s*(pkgname|pkgver|pkgrel|pkgbase)=(["\']?)(.*?)\2\s*$', re.MULTILINE
)

FUNCTION_NAMES = ("prepare", "build", "check", "package", "pkgver")
CHECKSUM_KEYS = ("sha256sums", "sha512sums", "b2sums", "md5sums")


def parse_pkgbuild(path: Path) -> RuleContext:
    source = path.read_text(errors="replace")
    parsed = parse_script(source)

    scalars: dict[str, str] = {}
    for m in _SCALAR_RE.finditer(source):
        key, _, value = m.group(1), m.group(2), m.group(3)
        scalars.setdefault(key, value)

    pkgname = scalars.get("pkgname")
    if pkgname is None:
        # split packages declare pkgname as an array instead of a scalar
        names = parsed.arrays.get("pkgname")
        pkgname = names[0] if names else None

    checksums = {k: v for k, v in parsed.arrays.items() if k in CHECKSUM_KEYS}
    functions = extract_functions(parsed.ast_nodes, FUNCTION_NAMES)

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
    )
