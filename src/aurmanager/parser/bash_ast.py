from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

import bashlex
from bashlex import errors as bashlex_errors

_ARRAY_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=\(")


def strip_array_literals(source: str) -> tuple[str, dict[str, str]]:
    """bashlex cannot parse bash array-literal assignments (`name=(...)`) anywhere in
    a script, and a single occurrence aborts parsing of the *entire* file rather than
    just that statement (verified empirically: bashlex.parse() is all-or-nothing).
    PKGBUILDs rely on arrays pervasively (source=(), sha256sums=(), depends=(), and
    often `local` arrays inside build()/package()), so an unmodified real-world
    PKGBUILD fails to parse essentially every time.

    This masks each array-literal statement in place (every character replaced with
    a space, newlines left as newlines) before the remainder is handed to bashlex for
    real AST parsing of control flow. Masking rather than deleting keeps the cleaned
    string exactly the same length as the original, so every bashlex node's character
    offset lines up 1:1 with an offset into the original source -- callers can use
    line_of(node.pos[0], original_source) directly. The raw inner text of each array
    is returned separately, to be split into elements by split_array_elements() --
    array contents are declarative data, not control flow, so they don't need a full
    bash AST.
    """
    extracted: dict[str, str] = {}
    out: list[str] = []
    n = len(source)
    last = 0
    while True:
        m = _ARRAY_ASSIGN_RE.search(source, last)
        if not m:
            out.append(source[last:])
            break
        out.append(source[last : m.start()])
        name = m.group(1)
        j = m.end()  # position just after the opening '('
        depth = 1
        in_squote = in_dquote = False
        start_inner = j
        while j < n and depth > 0:
            c = source[j]
            if in_squote:
                if c == "'":
                    in_squote = False
            elif in_dquote:
                if c == "\\":
                    j += 1
                elif c == '"':
                    in_dquote = False
            else:
                if c == "'":
                    in_squote = True
                elif c == '"':
                    in_dquote = True
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
            j += 1
        inner = source[start_inner : j - 1]
        extracted[name] = inner
        replaced_span = source[m.start() : j]
        out.append("".join(ch if ch == "\n" else " " for ch in replaced_span))
        last = j
    return "".join(out), extracted


def split_array_elements(inner: str) -> list[str]:
    """Quote-aware whitespace split of an array literal's inner text into elements,
    stripping quotes but leaving embedded $var references as literal text (this is
    static analysis, not evaluation)."""
    elements: list[str] = []
    buf: list[str] = []
    in_squote = in_dquote = False
    i = 0
    n = len(inner)
    while i < n:
        c = inner[i]
        if in_squote:
            if c == "'":
                in_squote = False
            else:
                buf.append(c)
            i += 1
            continue
        if in_dquote:
            if c == "\\" and i + 1 < n:
                buf.append(inner[i + 1])
                i += 2
                continue
            if c == '"':
                in_dquote = False
                i += 1
                continue
            buf.append(c)
            i += 1
            continue
        if c.isspace():
            if buf:
                elements.append("".join(buf))
                buf = []
            i += 1
            continue
        if c == "#":
            nl = inner.find("\n", i)
            if nl == -1:
                break
            i = nl
            continue
        if c == "'":
            in_squote = True
            i += 1
            continue
        if c == '"':
            in_dquote = True
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        elements.append("".join(buf))
    return elements


@dataclass
class ParsedScript:
    source: str
    ast_nodes: list[Any]
    arrays: dict[str, list[str]]
    parse_error: str | None


def parse_script(source: str) -> ParsedScript:
    cleaned, raw_arrays = strip_array_literals(source)
    arrays = {name: split_array_elements(inner) for name, inner in raw_arrays.items()}
    try:
        nodes = list(bashlex.parse(cleaned))
        return ParsedScript(source=source, ast_nodes=nodes, arrays=arrays, parse_error=None)
    except bashlex_errors.ParsingError as e:
        return ParsedScript(source=source, ast_nodes=[], arrays=arrays, parse_error=str(e))


def line_of(offset: int, source: str) -> int:
    return source.count("\n", 0, offset) + 1


def walk(node: Any) -> Iterator[Any]:
    """Depth-first walk over a bashlex AST subtree."""
    yield node
    children: list[Any] = []
    parts = getattr(node, "parts", None)
    if parts:
        children.extend(parts)
    lst = getattr(node, "list", None)
    if lst:
        children.extend(lst)
    for child in children:
        yield from walk(child)


def extract_functions(ast_nodes: list[Any], names: tuple[str, ...]) -> dict[str, Any]:
    functions: dict[str, Any] = {}
    for node in ast_nodes:
        if getattr(node, "kind", None) == "function":
            fname = node.parts[0].word
            if fname in names:
                functions[fname] = node
    return functions


def command_name(cmd_node: Any) -> str | None:
    """Best-effort command name of a bashlex CommandNode: the first part that carries
    a plain `.word` (skips redirects etc.)."""
    for p in getattr(cmd_node, "parts", []):
        w = getattr(p, "word", None)
        if w is not None:
            return w
    return None
