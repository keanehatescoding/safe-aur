from __future__ import annotations

from pathlib import Path

from ..model import RuleContext


def extract_added_lines(source: str) -> str:
    """Extract only the content a unified diff (plain `diff -u` or git-style
    `diff --git`) *adds*, replacing every other line (context, removed,
    `---`/`+++` file headers, `@@` hunk headers, `diff --git`/`index`
    preamble) with an empty line.

    Preserves line numbers 1:1 with the original .patch file -- each output
    line corresponds to the same line number in the source text, so
    line_and_snippet()/find_line_matches() report the line a reviewer would
    actually see when opening the patch. Verified against real `diff -u` and
    `git diff` output (both share the same core `+`/`-`/` ` line-prefix
    convention; git adds a `diff --git`/`index` preamble before it).

    Deliberately conservative: only lines that are genuinely new content
    ('+' prefix, excluding the '+++ b/file' header line, which also starts
    with '+') are kept. A construct split across a removed and an added line,
    or hidden only in context, is out of scope -- similar in spirit to why
    patches don't get full bash-AST treatment: they modify arbitrary file
    types, not just bash, so this is a best-effort textual view, not a real
    parse.

    Tracks whether the current line is inside a hunk (starts at an `@@ ...
    @@` header, resets at each file's `--- a/file` header) rather than just
    checking `startswith("+++")` unconditionally -- a naive check misreads a
    genuinely *added* line whose content itself starts with `+` (e.g. an
    added `++counter;`) as the `+++ b/file` header, since the raw diff line
    is `+` (the added-line marker) followed by content starting with `+`,
    producing `+++counter;`. `+++`/`---` only mean "file header" outside a
    hunk; inside one, a leading `+` always means "added line", regardless of
    what character follows. Verified empirically against that exact case,
    plus multi-file patches (each file's own `--- `/`+++ ` pair must reset
    hunk state for the next file's hunk to be tracked correctly).
    """
    out_lines: list[str] = []
    in_hunk = False
    for line in source.splitlines():
        if line.startswith("--- ") or line == "---":
            in_hunk = False
            out_lines.append("")
        elif line.startswith("@@"):
            in_hunk = True
            out_lines.append("")
        elif in_hunk and line.startswith("+"):
            out_lines.append(line[1:])
        else:
            out_lines.append("")
    return "\n".join(out_lines)


def parse_patch(path: Path) -> RuleContext:
    source = path.read_text(errors="replace")
    added = extract_added_lines(source)
    return RuleContext(
        file=path,
        source=added,
        ast=[],
        is_patch=True,
    )
