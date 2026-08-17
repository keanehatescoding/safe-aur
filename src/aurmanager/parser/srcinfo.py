from __future__ import annotations

from pathlib import Path


def parse_srcinfo_fields(path: Path) -> dict[str, list[str]]:
    """Parse a .SRCINFO file's pkgbase-level `key = value` lines into
    {key: [values...]} (repeated keys, e.g. multiple `source = ...` lines for
    an array, accumulate as a list in declaration order).

    Stops at the first `pkgname = ` line: split packages can override some
    fields per subpackage, but source/checksum arrays are declared once at
    the pkgbase level in the overwhelming majority of real PKGBUILDs, and a
    per-subpackage override is out of scope for this parser -- verified
    against real `makepkg --printsrcinfo` output, which emits a `pkgbase = `
    block first, then one `pkgname = ` block per (split) package.
    """
    fields: dict[str, list[str]] = {}
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("pkgname"):
            break
        if " = " not in stripped:
            continue
        key, _, value = stripped.partition(" = ")
        fields.setdefault(key, []).append(value)
    return fields
