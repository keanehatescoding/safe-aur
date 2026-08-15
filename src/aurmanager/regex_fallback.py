"""Secondary, textual detection layer for patterns bashlex can't cleanly represent as
AST nodes (long base64 blobs, hex-escape sequences, complex parameter expansions --
see the documented bashlex limitations in parser/bash_ast.py). Used only for patterns
that are inherently textual; control-flow patterns (pipelines, command sequencing)
are detected via the AST layer in rules/rce.py etc, not here.
"""

from __future__ import annotations

import re
from typing import Iterator, Pattern


def find_line_matches(source: str, pattern: Pattern[str]) -> Iterator[tuple[int, str, re.Match]]:
    for i, line in enumerate(source.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            yield i, line.strip(), m
